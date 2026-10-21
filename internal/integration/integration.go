// Package integration keeps the credentials helios itself uses, such as
// the object storage backups go to and the mail server alerts go through,
// in the machine's secrets store under helios's own name. Each integration
// is a named set of fields; values are typed in once and never shown.
package integration

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
)

// App is the reserved app whose secrets hold the integrations.
const App = manifest.ReservedApp

// Field is one value an integration needs.
type Field struct {
	// Name is lower_snake; the secret is stored as INTEGRATION_NAME.
	Name string
	// Prompt is what to ask for.
	Prompt string
	// Secret values are typed without echo and never listed.
	Secret bool
	// Optional fields may stay empty.
	Optional bool
	// Default applies when the value is empty.
	Default string
	// Choices limits the value to one of these.
	Choices []string
}

// Definition is one integration helios knows how to use.
type Definition struct {
	Name    string
	Purpose string
	Fields  []Field
}

// Names of the integrations.
const (
	StorageName     = "storage"
	EmailName       = "email"
	Email2Name      = "email2"
	PushoverName    = "pushover"
	NtfyName        = "ntfy"
	CloudflareName  = "cloudflare"
	LoomName        = "loom"
	LoomWebhookName = "loom_webhook"
)

// emailFields are what a mail server for alerts needs; email and email2
// ask the same.
var emailFields = []Field{
	{Name: "smtp_host", Prompt: "SMTP host"},
	{Name: "smtp_port", Prompt: "SMTP port (465 for TLS, 587 for STARTTLS)", Default: "587"},
	{Name: "smtp_user", Prompt: "SMTP user", Optional: true},
	{Name: "smtp_password", Prompt: "SMTP password", Secret: true, Optional: true},
	{Name: "from", Prompt: "from address"},
	{Name: "to", Prompt: "to address (several separated by commas)"},
}

// Definitions lists every integration, in the order they are shown.
var Definitions = []Definition{
	{
		Name:    StorageName,
		Purpose: "object storage for backups, one bucket per app",
		Fields: []Field{
			{Name: "kind", Prompt: "b2 (Backblaze) or s3 (any S3-compatible store)", Default: "b2", Choices: []string{"b2", "s3"}},
			{Name: "endpoint", Prompt: "S3 endpoint URL, for s3 only", Optional: true},
			{Name: "key_id", Prompt: "key ID"},
			{Name: "key", Prompt: "key", Secret: true},
			{Name: "bucket_prefix", Prompt: "bucket name prefix, such as kb (buckets are prefix-app)"},
			{Name: "password", Prompt: "backup encryption password; blank makes one the first time, then keep it with the recovery identity", Secret: true, Optional: true},
		},
	},
	{
		Name:    EmailName,
		Purpose: "alerts by email",
		Fields:  emailFields,
	},
	{
		Name:    Email2Name,
		Purpose: "a second mail server, for alerts the first one refuses",
		Fields:  emailFields,
	},
	{
		Name:    PushoverName,
		Purpose: "alerts on a phone through Pushover; critical ones ring until acknowledged",
		Fields: []Field{
			{Name: "app_token", Prompt: "Pushover application API token", Secret: true},
			{Name: "user_key", Prompt: "Pushover user or group key", Secret: true},
		},
	},
	{
		Name:    NtfyName,
		Purpose: "alerts on a phone through ntfy, instead of Pushover",
		Fields: []Field{
			{Name: "topic_url", Prompt: "topic URL, such as https://ntfy.sh/a-long-unguessable-topic", Secret: true},
			{Name: "token", Prompt: "access token, for a protected topic", Secret: true, Optional: true},
		},
	},
	{
		Name:    CloudflareName,
		Purpose: "DNS records for the apps' hostnames",
		Fields: []Field{
			{Name: "token", Prompt: "API token with Zone read and DNS edit on the zones", Secret: true},
			{Name: "api", Prompt: "API URL, only to test against something other than Cloudflare", Optional: true},
		},
	},
	{
		Name:    LoomName,
		Purpose: "who may reach a route marked auth: loom",
		Fields: []Field{
			{Name: "verify_url", Prompt: "the Core's verify endpoint, such as https://loom.example.com/api/cloud/auth/verify"},
		},
	},
	{
		Name:    LoomWebhookName,
		Purpose: "a Loom thread for each critical incident, through a scheduled task's webhook",
		Fields: []Field{
			{Name: "url", Prompt: "the task's webhook URL on the T3 Connect relay, https://<relay>/v1/hooks/<endpoint>/<task>/<token>", Secret: true},
			{Name: "secret", Prompt: "the secret the task checks the x-helios-signature header with, 16 to 512 characters", Secret: true},
		},
	},
}

// Lookup finds an integration by name.
func Lookup(name string) (Definition, bool) {
	for _, d := range Definitions {
		if d.Name == name {
			return d, true
		}
	}
	return Definition{}, false
}

// Names lists the integration names.
func Names() []string {
	names := make([]string, 0, len(Definitions))
	for _, d := range Definitions {
		names = append(names, d.Name)
	}
	return names
}

func (d Definition) key(field string) string {
	return strings.ToUpper(d.Name + "_" + field)
}

// WebhookSecretName and DeployKeyName name an app's webhook secret and
// deploy key in helios's own secrets. App names have no underscores, so
// the mapping is one to one.
func WebhookSecretName(app string) string { return hookSecretName("WEBHOOK_SECRET", app) }

// DeployKeyName is the deploy key's name; see WebhookSecretName.
func DeployKeyName(app string) string { return hookSecretName("DEPLOY_KEY", app) }

// OriginPullName names the CAs the edge's origin-pull hosts trust, all
// hosts in one value (edge.OriginPullTrust): a host's dots and hyphens
// can't be told apart in a secret's name.
const OriginPullName = "EDGE_ORIGIN_PULL"

func hookSecretName(kind, app string) string {
	return kind + "_" + strings.ToUpper(strings.ReplaceAll(app, "-", "_"))
}

// ErrNotSet means an integration hasn't been set up on this machine.
var ErrNotSet = errors.New("not set up")

var (
	bucketPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,19}$`)
	// Pushover's application tokens and user keys are 30 letters and digits.
	pushoverKeyPattern = regexp.MustCompile(`^[A-Za-z0-9]{30}$`)
	// ntfy topics are 1 to 64 letters, digits, hyphens and underscores.
	ntfyTopicPattern = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)
	ntfyTokenPattern = regexp.MustCompile(`^[!-~]+$`)
	// The relay names an environment's endpoint by 16 lowercase hex digits.
	loomEndpointPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	loomSecretPattern   = regexp.MustCompile(`^[ -~]{16,512}$`)
)

// Validate checks complete effective values without changing the secrets store.
// Callers applying a patch must merge it with current values first. Blank fields
// use the same defaults as Set; generated storage passwords remain optional.
func Validate(name string, values map[string]string) error {
	def, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("no integration named %q; there are %s", name, strings.Join(Names(), ", "))
	}
	known := map[string]bool{}
	complete := make(map[string]string, len(def.Fields))
	for _, f := range def.Fields {
		known[f.Name] = true
		v := strings.TrimSpace(values[f.Name])
		if v == "" {
			v = f.Default
		}
		if v == "" && !f.Optional {
			return fmt.Errorf("%s needs %s (%s)", name, f.Name, f.Prompt)
		}
		if v != "" && len(f.Choices) > 0 {
			match := false
			for _, choice := range f.Choices {
				match = match || choice == v
			}
			if !match {
				return fmt.Errorf("%s.%s must be one of %s", name, f.Name, strings.Join(f.Choices, ", "))
			}
		}
		complete[f.Name] = v
	}
	for k := range values {
		if !known[k] {
			return fmt.Errorf("%s has no field named %q", name, k)
		}
	}
	return validate(name, complete)
}

// Set stores an integration's values in one new version of helios's
// secrets and returns values it made up, such as a generated password,
// so the caller can show them exactly once.
//
// Setting an integration that is already set changes only the fields
// named: the rest keep their values. The storage password in particular
// is made once, when none is held, because a new one would leave every
// repository the old one opened unreadable.
func Set(store *secrets.Store, name string, values map[string]string) (version int, generated map[string]string, err error) {
	def, ok := Lookup(name)
	if !ok {
		return 0, nil, fmt.Errorf("no integration named %q; there are %s", name, strings.Join(Names(), ", "))
	}
	known := map[string]bool{}
	for _, f := range def.Fields {
		known[f.Name] = true
	}
	for k := range values {
		if !known[k] {
			return 0, nil, fmt.Errorf("%s has no field named %q", name, k)
		}
	}
	generated = map[string]string{}
	version, err = store.Update(App, func(all map[string]string) (map[string]*string, error) {
		current := storedFields(def, all)
		changes := map[string]*string{}
		for _, f := range def.Fields {
			v, named := values[f.Name]
			v = strings.TrimSpace(v)
			if !named {
				v = current[f.Name]
			}
			if v == "" {
				v = f.Default
			}
			if v == "" && name == StorageName && f.Name == "password" {
				if v = current[f.Name]; v == "" {
					var b [24]byte
					if _, err := rand.Read(b[:]); err != nil {
						return nil, err
					}
					v = hex.EncodeToString(b[:])
					generated[f.Name] = v
				}
			}
			if v == "" {
				if !f.Optional {
					return nil, fmt.Errorf("%s needs %s (%s)", name, f.Name, f.Prompt)
				}
				changes[def.key(f.Name)] = nil
				continue
			}
			if len(f.Choices) > 0 {
				match := false
				for _, c := range f.Choices {
					if c == v {
						match = true
					}
				}
				if !match {
					return nil, fmt.Errorf("%s.%s must be one of %s", name, f.Name, strings.Join(f.Choices, ", "))
				}
			}
			value := v
			changes[def.key(f.Name)] = &value
		}
		if err := Validate(name, fieldValues(def, changes)); err != nil {
			return nil, err
		}
		return changes, nil
	})
	if err != nil {
		return 0, nil, err
	}
	return version, generated, nil
}

func fieldValues(def Definition, changes map[string]*string) map[string]string {
	out := map[string]string{}
	for _, f := range def.Fields {
		if v := changes[def.key(f.Name)]; v != nil {
			out[f.Name] = *v
		}
	}
	return out
}

func validate(name string, v map[string]string) error {
	switch name {
	case StorageName:
		if v["kind"] == "s3" {
			if _, err := parseBaseEndpointURL(v["endpoint"]); err != nil {
				return fmt.Errorf("storage.endpoint: %w", err)
			}
		} else if v["endpoint"] != "" {
			return errors.New("storage.endpoint is for s3 only; Backblaze needs none")
		}
		if !bucketPrefixPattern.MatchString(v["bucket_prefix"]) {
			return errors.New("storage.bucket_prefix must be 2 to 20 lowercase letters, digits and hyphens")
		}
	case CloudflareName:
		if api := v["api"]; api != "" {
			if _, err := parseBaseEndpointURL(api); err != nil {
				return fmt.Errorf("cloudflare.api: %w", err)
			}
		}
	case EmailName, Email2Name:
		port, err := strconv.Atoi(v["smtp_port"])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s.smtp_port must be a port number", name)
		}
		if _, _, err := emailAddresses(name, v); err != nil {
			return err
		}
		if (v["smtp_user"] == "") != (v["smtp_password"] == "") {
			return fmt.Errorf("%s: give both smtp_user and smtp_password, or neither", name)
		}
	case PushoverName:
		// Neither value is echoed: both are credentials.
		for _, f := range []string{"app_token", "user_key"} {
			if !pushoverKeyPattern.MatchString(v[f]) {
				return fmt.Errorf("pushover.%s must be the 30 letters and digits Pushover shows", f)
			}
		}
	case NtfyName:
		if _, err := ParseNtfyTopic(v["topic_url"]); err != nil {
			return fmt.Errorf("ntfy.topic_url: %w", err)
		}
		if t := v["token"]; t != "" && !ntfyTokenPattern.MatchString(t) {
			return errors.New("ntfy.token must be one word with no spaces")
		}
	case LoomName:
		// The edge dials this on every request to a guarded route, so a URL
		// it cannot resolve into a host, a port and a path is a route that
		// answers nothing at all.
		if _, err := ParseVerifyURL(v["verify_url"]); err != nil {
			return fmt.Errorf("loom.verify_url: %w", err)
		}
	case LoomWebhookName:
		// Neither value is echoed: the URL carries the task's token.
		if err := checkLoomWebhookURL(v["url"]); err != nil {
			return fmt.Errorf("loom_webhook.url: %w", err)
		}
		if !loomSecretPattern.MatchString(v["secret"]) {
			return errors.New("loom_webhook.secret must be 16 to 512 printable ASCII characters")
		}
	}
	return nil
}

// Get returns an integration's values by field name. ErrNotSet when it
// isn't set up.
func Get(store *secrets.Store, name string) (map[string]string, error) {
	def, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("no integration named %q", name)
	}
	all, _, err := store.LoadCurrent(App)
	if err != nil {
		return nil, err
	}
	out := storedFields(def, all)
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: %w; run helios integration set %s", name, ErrNotSet, name)
	}
	return out, nil
}

func storedFields(def Definition, all map[string]string) map[string]string {
	out := map[string]string{}
	for _, f := range def.Fields {
		if v, ok := all[def.key(f.Name)]; ok {
			out[f.Name] = v
		}
	}
	return out
}

// Remove drops an integration's values.
func Remove(store *secrets.Store, name string) (int, error) {
	def, ok := Lookup(name)
	if !ok {
		return 0, fmt.Errorf("no integration named %q", name)
	}
	if _, err := Get(store, name); err != nil {
		return 0, err
	}
	changes := map[string]*string{}
	for _, f := range def.Fields {
		changes[def.key(f.Name)] = nil
	}
	return store.SetAll(App, changes)
}

// Status is an integration as listed: which fields are set, never the
// secret values.
type Status struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Set     bool   `json:"set"`
	// At is when the current values were stored.
	At time.Time `json:"at,omitempty"`
	// Fields holds plain values, and "(set)" for secrets.
	Fields map[string]string `json:"fields,omitempty"`
}

// List describes every integration.
func List(store *secrets.Store) ([]Status, error) {
	all, current, err := store.LoadCurrent(App)
	if err != nil {
		return nil, err
	}
	versions, err := store.Versions(App)
	if err != nil {
		return nil, err
	}
	// Ignore versions whose current pointer was never committed.
	committed := versions[:0]
	for _, info := range versions {
		if info.Version <= current {
			committed = append(committed, info)
		}
	}
	versions = committed
	loaded := map[int]map[string]string{current: all, 0: {}}
	values := func(version int) (map[string]string, error) {
		if raw, ok := loaded[version]; ok {
			return raw, nil
		}
		raw, err := store.Load(App, version)
		if err == nil {
			loaded[version] = raw
		}
		return raw, err
	}
	var out []Status
	for _, d := range Definitions {
		st := Status{Name: d.Name, Purpose: d.Purpose, Fields: map[string]string{}}
		for _, f := range d.Fields {
			v, ok := all[d.key(f.Name)]
			if !ok {
				continue
			}
			st.Set = true
			if f.Secret {
				st.Fields[f.Name] = "(set)"
			} else {
				st.Fields[f.Name] = v
			}
		}
		if st.Set {
			st.At, err = lastChange(versions, d, values)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// lastChange compares values as well as field presence. Updating a credential
// must advance its timestamp; unrelated changes in the shared store must not.
func lastChange(versions []secrets.VersionInfo, d Definition, values func(int) (map[string]string, error)) (time.Time, error) {
	for i, info := range versions {
		current, err := values(info.Version)
		if err != nil {
			return time.Time{}, err
		}
		olderVersion := 0
		if i+1 < len(versions) {
			olderVersion = versions[i+1].Version
		}
		older, err := values(olderVersion)
		if err != nil {
			return time.Time{}, err
		}
		for _, field := range d.Fields {
			key := d.key(field.Name)
			value, exists := current[key]
			previous, existed := older[key]
			if exists != existed || value != previous {
				return info.At, nil
			}
		}
	}
	return time.Time{}, nil
}

// Storage is the object storage backups go to.
type Storage struct {
	Kind         string
	Endpoint     string
	KeyID        string
	Key          string
	BucketPrefix string
	Password     string
}

// LoomVerifiedHeader and LoomVerifiedValue are what a Core's verify
// endpoint says about itself, and what the edge insists on seeing before it
// treats an answer as a yes.
//
// The Core serves a single-page app, so an unknown path answers 200 with
// that app's HTML rather than a 404. Without this, a guard pointed at a
// Core too old to have the endpoint would read that 200 as permission and
// let everyone through: open, and looking guarded. With it, such a Core
// denies everything instead, which is visible the first time anyone looks.
const (
	LoomVerifiedHeader = "X-Loom-Verified"
	LoomVerifiedValue  = "1"
)

// Loom is where the edge asks whether a request is signed in.
type Loom struct {
	// VerifyURL answers 2xx for a signed-in request and anything else for
	// one that is not.
	VerifyURL string
}

// LoadLoom reads the loom integration. A machine with no loom integration
// gets a nil Loom and no error, because most machines have no Core and
// routes on them are open.
func LoadLoom(store *secrets.Store) (*Loom, error) {
	v, err := Get(store, LoomName)
	if err != nil {
		return nil, err
	}
	if v["verify_url"] == "" {
		return nil, nil
	}
	return &Loom{VerifyURL: v["verify_url"]}, nil
}

// LoomWebhook is the Loom scheduled task a critical incident opens a thread
// through.
type LoomWebhook struct {
	// URL is the task's webhook URL on the T3 Connect relay. Its last
	// segment is the task's token, so it is a credential.
	URL string
	// Secret signs each body, as the task's signature check expects.
	Secret string
}

// LoadLoomWebhook reads the loom_webhook integration. ErrNotSet when it
// isn't set up.
func LoadLoomWebhook(store *secrets.Store) (*LoomWebhook, error) {
	v, err := Get(store, LoomWebhookName)
	if err != nil {
		return nil, err
	}
	// Checked again here, so nothing but the relay's shape is ever sent to.
	if err := validate(LoomWebhookName, v); err != nil {
		return nil, err
	}
	return &LoomWebhook{URL: v["url"], Secret: v["secret"]}, nil
}

// checkLoomWebhookURL accepts only a task's webhook URL on the T3 Connect
// relay: https://<relay>/v1/hooks/<endpoint>/<task>/<token>. Loom's direct
// /api/hooks route is refused, because the answers the leg reads, such as
// a 202 for a request held while Loom is offline, are the relay's.
// The token is a credential, so errors never echo it.
func checkLoomWebhookURL(raw string) error {
	u, err := parseEndpointURL(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return errors.New("URL must start with https://")
	}
	if strings.ContainsAny(raw, "?#") {
		return errors.New("URL must not have a query or a fragment")
	}
	// The path is read as written, so an escaped slash stays in its segment,
	// as the relay reads it.
	parts := strings.Split(u.EscapedPath(), "/")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "v1" || parts[2] != "hooks" ||
		!loomEndpointPattern.MatchString(parts[3]) || parts[4] == "" || parts[5] == "" {
		return errors.New("URL must be the task's relay webhook URL, https://<relay>/v1/hooks/<endpoint>/<task>/<token>, with a 16 hex digit endpoint")
	}
	return nil
}

// LoadStorage reads the storage integration.
func LoadStorage(store *secrets.Store) (*Storage, error) {
	v, err := Get(store, StorageName)
	if err != nil {
		return nil, err
	}
	return &Storage{Kind: v["kind"], Endpoint: v["endpoint"], KeyID: v["key_id"], Key: v["key"], BucketPrefix: v["bucket_prefix"], Password: v["password"]}, nil
}

// Bucket names an app's bucket.
func (s Storage) Bucket(app string) string { return s.BucketPrefix + "-" + app }

// Repository is the restic repository string for a bucket.
func (s Storage) Repository(bucket string) string {
	if s.Kind == "s3" {
		return "s3:" + strings.TrimSuffix(s.Endpoint, "/") + "/" + bucket
	}
	return "b2:" + bucket + ":/"
}

// Env returns the credentials as restic reads them.
func (s Storage) Env() []string {
	if s.Kind == "s3" {
		return []string{"AWS_ACCESS_KEY_ID=" + s.KeyID, "AWS_SECRET_ACCESS_KEY=" + s.Key}
	}
	return []string{"B2_ACCOUNT_ID=" + s.KeyID, "B2_ACCOUNT_KEY=" + s.Key}
}

// Describe says where backups go, without credentials.
func (s Storage) Describe() string {
	if s.Kind == "s3" {
		return "s3 at " + s.Endpoint + ", buckets " + s.BucketPrefix + "-*"
	}
	return "Backblaze B2, buckets " + s.BucketPrefix + "-*"
}

// Email is a mail server alerts go through.
type Email struct {
	// Name is the integration it came from: email or email2.
	Name     string
	Host     string
	Port     int
	User     string
	Password string
	From     string
	To       []string
}

// LoadEmail reads the email integration.
func LoadEmail(store *secrets.Store) (*Email, error) {
	return loadEmail(store, EmailName)
}

// LoadEmailRelays reads the mail servers alerts go through, in the order
// they are tried: email, then email2. Either may be unset; none set is
// an empty list.
func LoadEmailRelays(store *secrets.Store) ([]Email, error) {
	var relays []Email
	for _, name := range []string{EmailName, Email2Name} {
		e, err := loadEmail(store, name)
		if errors.Is(err, ErrNotSet) {
			continue
		}
		if err != nil {
			return nil, err
		}
		relays = append(relays, *e)
	}
	return relays, nil
}

func loadEmail(store *secrets.Store, name string) (*Email, error) {
	v, err := Get(store, name)
	if err != nil {
		return nil, err
	}
	from, to, err := emailAddresses(name, v)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(v["smtp_port"])
	return &Email{Name: name, Host: v["smtp_host"], Port: port, User: v["smtp_user"], Password: v["smtp_password"], From: from, To: to}, nil
}

// emailAddresses keeps the SMTP envelope to mailboxes, even when a person
// enters display names. Only the recipient field accepts an address list.
func emailAddresses(name string, values map[string]string) (string, []string, error) {
	from, err := mail.ParseAddress(values["from"])
	if err != nil {
		return "", nil, fmt.Errorf("%s.from: isn't an address", name)
	}
	recipients, err := mail.ParseAddressList(values["to"])
	if err != nil || len(recipients) == 0 {
		return "", nil, fmt.Errorf("%s.to: isn't an address list", name)
	}
	to := make([]string, 0, len(recipients))
	for _, address := range recipients {
		to = append(to, address.Address)
	}
	return from.Address, to, nil
}

// Pushover is the Pushover application and user alerts go to.
type Pushover struct {
	AppToken string
	UserKey  string
}

// LoadPushover reads the pushover integration.
func LoadPushover(store *secrets.Store) (*Pushover, error) {
	v, err := Get(store, PushoverName)
	if err != nil {
		return nil, err
	}
	return &Pushover{AppToken: v["app_token"], UserKey: v["user_key"]}, nil
}

// Ntfy is the ntfy topic alerts are published to.
type Ntfy struct {
	NtfyTopic
	// Token is empty for an open topic.
	Token string
}

// NtfyTopic is a topic URL split into the server it is published through
// and the topic's name.
type NtfyTopic struct {
	// Server is where notices are published, ending in a slash.
	Server string
	Topic  string
}

// ParseNtfyTopic splits a topic URL, such as https://ntfy.sh/topic, into
// its server and topic. The URL is a credential on a public server, since
// anyone who knows it can read the topic, so errors never echo it.
func ParseNtfyTopic(raw string) (NtfyTopic, error) {
	u, err := parseEndpointURL(strings.TrimSpace(raw))
	if err != nil {
		return NtfyTopic{}, err
	}
	if u.RawQuery != "" {
		return NtfyTopic{}, errors.New("URL must not have a query")
	}
	// The topic is read from the path as written, so an escaped slash
	// can't move part of it into the server.
	escaped := u.EscapedPath()
	topic := escaped[strings.LastIndex(escaped, "/")+1:]
	if !ntfyTopicPattern.MatchString(topic) {
		return NtfyTopic{}, errors.New("URL must end in a topic of 1 to 64 letters, digits, hyphens and underscores")
	}
	u.Path = strings.TrimSuffix(u.Path, topic)
	u.RawPath = strings.TrimSuffix(u.RawPath, topic)
	return NtfyTopic{Server: u.String(), Topic: topic}, nil
}

// LoadNtfy reads the ntfy integration.
func LoadNtfy(store *secrets.Store) (*Ntfy, error) {
	v, err := Get(store, NtfyName)
	if err != nil {
		return nil, err
	}
	topic, err := ParseNtfyTopic(v["topic_url"])
	if err != nil {
		return nil, fmt.Errorf("ntfy.topic_url: %w", err)
	}
	return &Ntfy{NtfyTopic: topic, Token: v["token"]}, nil
}

// Cloudflare is the DNS API token, and the API it is for.
type Cloudflare struct {
	Token string
	// API is empty for Cloudflare itself.
	API string
}

// LoadCloudflare reads the cloudflare integration.
func LoadCloudflare(store *secrets.Store) (*Cloudflare, error) {
	v, err := Get(store, CloudflareName)
	if err != nil {
		return nil, err
	}
	return &Cloudflare{Token: v["token"], API: v["api"]}, nil
}

// Verify is a verify_url broken into the parts the edge dials it by.
type Verify struct {
	Dial string
	Path string
	TLS  bool
	Host string
}

// ParseVerifyURL splits a Core's verify endpoint into a dial address and a
// path, filling in the port the scheme implies.
func ParseVerifyURL(raw string) (*Verify, error) {
	u, err := parseEndpointURL(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("URL names no path; give the verify endpoint itself")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return &Verify{
		Dial: net.JoinHostPort(u.Hostname(), port),
		Path: u.RequestURI(),
		TLS:  u.Scheme == "https",
		Host: u.Hostname(),
	}, nil
}

// These endpoints are also shown as public configuration. Credentials must
// stay in their separate sealed fields, and rejected URLs never echo input.
func parseEndpointURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("URL must start with https:// or http:// and name a host")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("URL must not contain credentials or a fragment")
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("URL port must be 1 to 65535")
		}
	}
	return u, nil
}

// Base endpoints have resource paths appended by their clients. A query would
// swallow those paths and could expose a credential as public configuration.
func parseBaseEndpointURL(raw string) (*url.URL, error) {
	u, err := parseEndpointURL(raw)
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("base URL must not have a query")
	}
	return u, nil
}
