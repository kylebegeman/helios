package objectstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// s3DefaultRegion signs requests when the endpoint's name says nothing
// about a region. Self-hosted S3 servers accept it; a store that insists on
// another names it in its refusal, and the request is signed again.
const s3DefaultRegion = "us-east-1"

type s3 struct {
	keyID, key string
	// base is the endpoint without a trailing slash; buckets are addressed
	// by path under it, as restic addresses them.
	base   *url.URL
	region string
	http   *http.Client
	wait   func(context.Context, int) error
	// settle waits before a bucket is listed again because the store still
	// lists a file it has just deleted.
	settle func(context.Context, time.Duration) error
	now    func() time.Time

	// plain is set once the store has shown that it has no listing of
	// versions: it refused one, or answered one with a plain listing. It
	// keeps none, so its objects are everything a bucket holds.
	plain bool
	// versioned is set once the store has listed versions. Such a store is
	// never read through the plain listing afterwards: that shows only the
	// newest version of each file, and deleting by it would leave the rest.
	versioned bool
}

func newS3(c Config) (*s3, error) {
	u, err := url.Parse(strings.TrimSuffix(c.Endpoint, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" {
		return nil, errors.New("the s3 endpoint must be an http or https address")
	}
	return &s3{keyID: c.KeyID, key: c.Key, base: u, region: regionOf(u.Hostname()), http: newHTTP(), wait: backoff, settle: pause, now: time.Now}, nil
}

var regionInHost = regexp.MustCompile(`^s3[.-]([a-z0-9-]+)\.(amazonaws\.com|backblazeb2\.com|wasabisys\.com)$`)

// regionOf reads the region out of the endpoint names that carry one.
func regionOf(host string) string {
	if m := regionInHost.FindStringSubmatch(host); m != nil {
		return m[1]
	}
	if strings.HasSuffix(host, ".r2.cloudflarestorage.com") {
		return "auto"
	}
	return s3DefaultRegion
}

// escape encodes as SigV4 requires: everything but unreserved characters,
// and "/" too unless it separates path segments.
func escape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		values := append([]string{}, q[k]...)
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, escape(k, false)+"="+escape(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// emptyPayload is the SHA-256 of no body. Every request here has none.
const emptyPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// sign returns the Authorization header for a bodyless request, AWS
// Signature Version 4, signing the host, payload hash and date headers.
func sign(keyID, key, region, method, host, escapedPath, query string, at time.Time) string {
	stamp := at.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	scope := day + "/" + region + "/s3/aws4_request"
	const signed = "host;x-amz-content-sha256;x-amz-date"
	request := strings.Join([]string{
		method, escapedPath, query,
		"host:" + host, "x-amz-content-sha256:" + emptyPayload, "x-amz-date:" + stamp, "",
		signed, emptyPayload,
	}, "\n")
	digest := sha256.Sum256([]byte(request))
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", stamp, scope, hex.EncodeToString(digest[:])}, "\n")
	k := hmacSHA256([]byte("AWS4"+key), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + keyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(hmacSHA256(k, toSign))
}

type s3Refusal struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
	Region  string `xml:"Region"`
}

// do runs one request against a path under the endpoint and decodes an XML
// answer into out.
func (c *s3) do(ctx context.Context, method, path string, q url.Values, out any) error {
	escaped := escape(strings.TrimSuffix(c.base.Path, "/")+path, true)
	query := canonicalQuery(q)
	var last error
	resigned := false
	for n := 0; n < attempts; n++ {
		if n > 0 && !resigned {
			if err := c.wait(ctx, n-1); err != nil {
				return errors.Join(last, err)
			}
		}
		resigned = false
		target := c.base.Scheme + "://" + c.base.Host + escaped
		if query != "" {
			target += "?" + query
		}
		req, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			return err
		}
		at := c.now()
		req.Header.Set("x-amz-date", at.UTC().Format("20060102T150405Z"))
		req.Header.Set("x-amz-content-sha256", emptyPayload)
		req.Header.Set("Authorization", sign(c.keyID, c.key, c.region, method, c.base.Host, escaped, query, at))
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			last = err
			continue
		}
		body, err := readBody(resp)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil || len(body) == 0 {
				return nil
			}
			if err := xml.Unmarshal(body, out); err != nil {
				return fmt.Errorf("read storage answer: %w", err)
			}
			return nil
		}
		var refusal s3Refusal
		_ = xml.Unmarshal(body, &refusal)
		last = &APIError{Status: resp.StatusCode, Code: refusal.Code, Message: refusal.Message}
		// A store that wants another region says which. Sign again for it,
		// once per region.
		if refusal.Code == "AuthorizationHeaderMalformed" && refusal.Region != "" && refusal.Region != c.region {
			c.region = refusal.Region
			resigned = true
			continue
		}
		if !retryable(resp.StatusCode) || resp.StatusCode == http.StatusNotImplemented {
			return last
		}
	}
	return last
}

// refusedAs reports whether err is the store answering with one of codes.
func refusedAs(err error, codes ...string) bool {
	var refusal *APIError
	if !errors.As(err, &refusal) {
		return false
	}
	for _, code := range codes {
		if refusal.Code == code {
			return true
		}
	}
	return false
}

// unsupported reports a store that does not implement the call at all.
func unsupported(err error) bool {
	var refusal *APIError
	return errors.As(err, &refusal) && (refusal.Status == http.StatusNotImplemented || refusal.Code == "NotImplemented")
}

type s3Buckets struct {
	Owner struct {
		ID string `xml:"ID"`
	} `xml:"Owner"`
	Buckets []struct {
		Name string `xml:"Name"`
	} `xml:"Buckets>Bucket"`
}

func (c *s3) list(ctx context.Context) (*s3Buckets, error) {
	var out s3Buckets
	if err := c.do(ctx, http.MethodGet, "/", nil, &out); err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}
	return &out, nil
}

func (c *s3) Account(ctx context.Context) (string, error) {
	out, err := c.list(ctx)
	if err != nil {
		return "", err
	}
	account := "s3:" + c.base.Host + strings.TrimSuffix(c.base.Path, "/")
	if out.Owner.ID != "" {
		account += "#" + out.Owner.ID
	}
	return account, nil
}

func (c *s3) Buckets(ctx context.Context) ([]Bucket, error) {
	out, err := c.list(ctx)
	if err != nil {
		return nil, err
	}
	buckets := make([]Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name == "" {
			return nil, errors.New("list buckets: a bucket without a name")
		}
		buckets = append(buckets, Bucket{Name: b.Name})
	}
	return buckets, nil
}

// s3Object is one file version, delete marker or plain object.
type s3Object struct {
	Key          string    `xml:"Key"`
	VersionID    string    `xml:"VersionId"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

// The root element of a store's answer says which listing it is: of a
// bucket's versions, or the plain one of its objects, in either version of
// that call.
const (
	s3VersionListing = "ListVersionsResult"
	s3PlainListing   = "ListBucketResult"
)

// s3UploadListing is the root element of a listing of unfinished uploads.
const s3UploadListing = "ListMultipartUploadsResult"

// s3EmptyPages is how many pages in a row a listing may hold nothing and
// still say there is more.
const s3EmptyPages = 16

// markers holds the markers of a listing to the order of its names. A page
// says where the next one carries on: after a name and, among the entries
// of that name, after an id. The names come in order, so each marker must
// lie after the one before it.
type markers struct {
	key  string
	seen map[string]bool
}

// passed takes the marker a page named and reports whether the listing has
// been there already.
func (m *markers) passed(key, id string) bool {
	switch {
	case m.seen == nil || key > m.key:
		m.key, m.seen = key, map[string]bool{}
	case key < m.key || m.seen[id]:
		return true
	}
	m.seen[id] = true
	return false
}

// noListing is the error for an answer that is not the listing asked for.
// Read as one it would hold nothing, and a full bucket would pass for an
// empty one.
func noListing(root string) error {
	if root == "" {
		return errors.New("the store answered with nothing")
	}
	return fmt.Errorf("the store answered with %s, which is not a listing of the bucket", root)
}

// objects walks everything a bucket holds, in the order of its names: every
// version and delete marker where the store keeps versions, every object
// where it does not.
func (c *s3) objects(ctx context.Context, bucket string, each func([]s3Object) error) error {
	if bucket == "" || strings.Contains(bucket, "/") {
		return errors.New("not a bucket name")
	}
	if !c.plain {
		if listed, err := c.versions(ctx, bucket, each); listed || err != nil {
			return err
		}
	}
	return c.plainObjects(ctx, bucket, each)
}

// versions walks every version and delete marker in a bucket. It reports
// false, with each not called, for a store that has no such listing and is
// read through its plain one from then on.
//
// A store says so in one of two ways. It refuses the call as not
// implemented, or it ignores what was asked and answers with the plain
// listing of the bucket, which is told by the answer's root element. Read
// as a listing of versions, that answer holds none, and a full bucket would
// pass for an empty one.
//
// Either is taken only as the first thing the store ever says about
// versions. A store that has listed versions and then will not is not one
// without versions, and its plain listing would leave versions out.
//
// Each marker must lie after the one before it (see markers). That, and the
// bound on pages that hold nothing, is what ends a listing whose store hands
// out the same marker for ever.
func (c *s3) versions(ctx context.Context, bucket string, each func([]s3Object) error) (bool, error) {
	q := url.Values{"versions": {""}, "max-keys": {"1000"}}
	// empty counts the pages in a row that held nothing.
	var after markers
	empty := 0
	for {
		var out struct {
			XMLName             xml.Name
			IsTruncated         bool       `xml:"IsTruncated"`
			NextKeyMarker       string     `xml:"NextKeyMarker"`
			NextVersionIDMarker string     `xml:"NextVersionIdMarker"`
			Versions            []s3Object `xml:"Version"`
			DeleteMarkers       []s3Object `xml:"DeleteMarker"`
		}
		err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out)
		switch {
		case unsupported(err) && c.versioned:
			return false, fmt.Errorf("list file versions: the store listed versions and now refuses to: %w", err)
		case unsupported(err):
			c.plain = true
			return false, nil
		case err != nil:
			return false, fmt.Errorf("list file versions: %w", err)
		case out.XMLName.Local == s3PlainListing && c.versioned:
			return false, errors.New("list file versions: the store listed versions and now answers with a plain listing")
		case out.XMLName.Local == s3PlainListing:
			c.plain = true
			return false, nil
		case out.XMLName.Local != s3VersionListing:
			return false, fmt.Errorf("list file versions: %w", noListing(out.XMLName.Local))
		}
		c.versioned = true
		// A page lists its versions and its delete markers apart. They
		// are put back in the order of their names, which is the order
		// the pages themselves come in.
		page := append(out.Versions, out.DeleteMarkers...)
		sort.SliceStable(page, func(i, j int) bool { return page[i].Key < page[j].Key })
		if err := each(page); err != nil {
			return true, err
		}
		if !out.IsTruncated {
			return true, nil
		}
		if out.NextKeyMarker == "" {
			return true, errors.New("list file versions: a truncated page without a marker")
		}
		if len(page) > 0 {
			empty = 0
		} else if empty++; empty > s3EmptyPages {
			return true, fmt.Errorf("list file versions: the listing does not end: %d pages in a row held nothing and said there was more", empty)
		}
		if after.passed(out.NextKeyMarker, out.NextVersionIDMarker) {
			return true, fmt.Errorf("list file versions: the listing does not carry on after %s: the store named a marker it had already passed", after.key)
		}
		q.Set("key-marker", out.NextKeyMarker)
		q.Del("version-id-marker")
		if out.NextVersionIDMarker != "" {
			q.Set("version-id-marker", out.NextVersionIDMarker)
		}
	}
}

// plainObjects walks a bucket's objects through the plain listing, for a
// store that keeps no versions.
//
// The listing is asked for in its second version, which carries on from a
// token. A store that knows only the first version answers in that one,
// with no token, and is carried on as that version is: after the marker it
// names, or after the last name of the page.
//
// Either way a plain listing names each object once, in the order of the
// names, so each page must start after the last one ended. That, and a
// bound on pages that hold nothing, is what ends a listing whose store does
// not carry on from where it was told to: it would otherwise hand out the
// same page for ever.
func (c *s3) plainObjects(ctx context.Context, bucket string, each func([]s3Object) error) error {
	q := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	// last is the last name listed so far; empty counts the pages in a row
	// that held nothing.
	last, listed, empty := "", false, 0
	for {
		var out struct {
			XMLName     xml.Name
			IsTruncated bool       `xml:"IsTruncated"`
			Next        string     `xml:"NextContinuationToken"`
			NextMarker  string     `xml:"NextMarker"`
			Contents    []s3Object `xml:"Contents"`
		}
		if err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out); err != nil {
			return fmt.Errorf("list files: %w", err)
		}
		if out.XMLName.Local != s3PlainListing {
			return fmt.Errorf("list files: %w", noListing(out.XMLName.Local))
		}
		if n := len(out.Contents); n > 0 {
			if listed && out.Contents[0].Key <= last {
				return fmt.Errorf("list files: the listing does not carry on after %s: the store gave a page it had already given", last)
			}
			last, listed, empty = out.Contents[n-1].Key, true, 0
		} else if empty++; out.IsTruncated && empty > s3EmptyPages {
			return fmt.Errorf("list files: the listing does not end: %d pages in a row held nothing and said there was more", empty)
		}
		if err := each(out.Contents); err != nil {
			return err
		}
		if !out.IsTruncated {
			return nil
		}
		if out.Next != "" {
			q.Set("continuation-token", out.Next)
			continue
		}
		marker := out.NextMarker
		if marker == "" && len(out.Contents) > 0 {
			marker = last
		}
		if marker == "" {
			return errors.New("list files: a truncated page without a token or a name to carry on after")
		}
		q.Set("marker", marker)
	}
}

func (c *s3) Usage(ctx context.Context, b Bucket) (Usage, error) {
	var u Usage
	err := c.objects(ctx, b.Name, func(objects []s3Object) error {
		for _, o := range objects {
			u.Files++
			u.Bytes += o.Size
			if o.LastModified.After(u.LastWrite) {
				u.LastWrite = o.LastModified.UTC()
			}
		}
		return nil
	})
	return u, err
}

type s3Upload struct {
	Key       string    `xml:"Key"`
	UploadID  string    `xml:"UploadId"`
	Initiated time.Time `xml:"Initiated"`
}

// uploads lists a bucket's unfinished multipart uploads. Their parts are
// billed and keep the bucket from being deleted.
//
// A store without such uploads says so as one without versions does: it
// refuses the call, or it answers with the plain listing of the bucket,
// which is told by the answer's root element. Either is taken only as the
// first answer. The listing is held to the order of its markers and to the
// bound on empty pages, as the listings of files are.
func (c *s3) uploads(ctx context.Context, bucket string) ([]s3Upload, error) {
	var all []s3Upload
	q := url.Values{"uploads": {""}, "max-uploads": {"1000"}}
	var after markers
	empty := 0
	for first := true; ; first = false {
		var out struct {
			XMLName            xml.Name
			IsTruncated        bool       `xml:"IsTruncated"`
			NextKeyMarker      string     `xml:"NextKeyMarker"`
			NextUploadIDMarker string     `xml:"NextUploadIdMarker"`
			Uploads            []s3Upload `xml:"Upload"`
		}
		err := c.do(ctx, http.MethodGet, "/"+bucket, q, &out)
		switch {
		case unsupported(err) && first:
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("list unfinished uploads: %w", err)
		case out.XMLName.Local == s3PlainListing && first:
			return nil, nil
		case out.XMLName.Local != s3UploadListing:
			return nil, fmt.Errorf("list unfinished uploads: %w", noListing(out.XMLName.Local))
		}
		all = append(all, out.Uploads...)
		if !out.IsTruncated {
			return all, nil
		}
		if out.NextKeyMarker == "" {
			return nil, errors.New("list unfinished uploads: a truncated page without a marker")
		}
		if len(out.Uploads) > 0 {
			empty = 0
		} else if empty++; empty > s3EmptyPages {
			return nil, fmt.Errorf("list unfinished uploads: the listing does not end: %d pages in a row held nothing and said there was more", empty)
		}
		if after.passed(out.NextKeyMarker, out.NextUploadIDMarker) {
			return nil, fmt.Errorf("list unfinished uploads: the listing does not carry on after %s: the store named a marker it had already passed", after.key)
		}
		q.Set("key-marker", out.NextKeyMarker)
		q.Set("upload-id-marker", out.NextUploadIDMarker)
	}
}

// examine reads the whole bucket against the check and returns its
// unfinished uploads.
func (c *s3) examine(ctx context.Context, b Bucket, check Check) ([]s3Upload, error) {
	pending, err := c.uploads(ctx, b.Name)
	if err != nil {
		return nil, err
	}
	for _, u := range pending {
		if err := check.file(u.Key, u.Initiated); err != nil {
			return nil, err
		}
	}
	if err := c.objects(ctx, b.Name, func(objects []s3Object) error {
		for _, o := range objects {
			if err := check.file(o.Key, o.LastModified); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return pending, check.whole()
}

func (c *s3) Examine(ctx context.Context, b Bucket, check Check) error {
	_, err := c.examine(ctx, b, check)
	return err
}

// errNextPage ends a listing after the one page that was deleted.
var errNextPage = errors.New("next page")

// stillListed is a listing that starts with the file that was just deleted.
type stillListed struct{ key string }

func (e *stillListed) Error() string {
	return fmt.Sprintf("delete %s: the store still lists it after deleting it", e.key)
}

// pause waits for d, or returns early with ctx's error.
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// relistAfter is how long to wait before each new listing of a bucket whose
// store still lists a file it has just deleted, and so how many are asked
// for before the deletion gives up. A listing that trails its deletions
// catches up within a moment; one still wrong after these is not trailing.
var relistAfter = []time.Duration{250 * time.Millisecond, time.Second, 4 * time.Second}

func (c *s3) DeleteBucket(ctx context.Context, b Bucket, check Check) (Deleted, error) {
	var d Deleted
	// Read the whole bucket before deleting any of it, so a bucket that
	// does not pass loses nothing. The pages are checked again below for
	// what arrives while the deletion runs.
	pending, err := c.examine(ctx, b, check)
	if err != nil {
		return d, err
	}
	// The unfinished uploads go before any file does. Were they left for
	// last, a deletion that stopped there would leave a bucket with uploads
	// and nothing to say whose they are.
	for _, u := range pending {
		err := c.do(ctx, http.MethodDelete, "/"+b.Name+"/"+u.Key, url.Values{"uploadId": {u.UploadID}}, nil)
		if err != nil && !refusedAs(err, "NoSuchUpload") {
			return d, fmt.Errorf("cancel unfinished upload %s: %w", u.Key, err)
		}
	}
	// One page is deleted at a time, and the listing then starts again
	// from the top. A listing carried on past a page that was just deleted
	// would be told to continue after a file version that is gone, and what
	// a store does with that is not ours to rely on.
	//
	// A store's listing may be a moment behind its deletions and start with
	// the file that just went. It is then asked again, a few times and a
	// little later each time, before the deletion gives up: stopping at the
	// first such answer would delete one page a night.
	for last, behind := "", 0; ; {
		first, emptied := "", true
		var listedStill *stillListed
		err = c.objects(ctx, b.Name, func(objects []s3Object) error {
			if len(objects) == 0 {
				return nil
			}
			emptied, first = false, objects[0].Key+"@"+objects[0].VersionID
			if first == last {
				return &stillListed{objects[0].Key}
			}
			// The whole page is checked before any of it is deleted.
			for _, o := range objects {
				if err := check.file(o.Key, o.LastModified); err != nil {
					return err
				}
			}
			for _, o := range objects {
				var q url.Values
				if o.VersionID != "" {
					q = url.Values{"versionId": {o.VersionID}}
				}
				err := c.do(ctx, http.MethodDelete, "/"+b.Name+"/"+o.Key, q, nil)
				if err != nil && !refusedAs(err, "NoSuchKey", "NoSuchVersion") {
					return fmt.Errorf("delete %s: %w", o.Key, err)
				}
				d.Files++
				d.Bytes += o.Size
			}
			return errNextPage
		})
		if errors.As(err, &listedStill) {
			if behind == len(relistAfter) {
				return d, err
			}
			if err := c.settle(ctx, relistAfter[behind]); err != nil {
				return d, err
			}
			behind++
			continue
		}
		if err != nil && !errors.Is(err, errNextPage) {
			return d, err
		}
		if emptied {
			break
		}
		last, behind = first, 0
	}
	if err := c.do(ctx, http.MethodDelete, "/"+b.Name, nil, nil); err != nil {
		return d, fmt.Errorf("delete bucket: %w", err)
	}
	d.Bucket = true
	return d, nil
}
