package manifest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

//go:generate go run ../../cmd/helios-schema -out ../../schema/helios.schema.json -legacy-out ../../schema/bedrock.schema.json

// SchemaVersion identifies the published editor schema contract. It does not
// add a version field to helios.yaml; Parse remains the deploy authority.
const SchemaVersion = "1"

// SchemaID is also the URL used by YAML editors to discover the generated file.
const SchemaID = "https://raw.githubusercontent.com/kylebegeman/helios/next/schema/helios.schema.json"

// LegacySchemaID remains published for existing editor annotations.
const LegacySchemaID = "https://raw.githubusercontent.com/kylebegeman/bedrock/next/schema/bedrock.schema.json"

type schemaObject = map[string]any

// JSONSchema generates the editor schema from the manifest's YAML-tagged Go
// types, then adds constraints that describe Validate's workload semantics.
// Cross-reference checks, cron parsing and source checks remain in CheckSource.
func JSONSchema() ([]byte, error) { return jsonSchema(SchemaID) }

// LegacyJSONSchema keeps the previous editor URL usable during migration.
func LegacyJSONSchema() ([]byte, error) { return jsonSchema(LegacySchemaID) }

func jsonSchema(id string) ([]byte, error) {
	g := schemaGenerator{defs: schemaObject{}}
	schema := g.typeSchema(reflect.TypeFor[Manifest]())
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["$id"] = id
	schema["title"] = "Helios app manifest"
	schema["description"] = "One app's workloads, routes, data, checks, secrets and backups. Run helios check for complete offline validation, including cross-field references and source files."
	schema["x-helios-schema-version"] = SchemaVersion
	schema["x-bedrock-schema-version"] = SchemaVersion
	schema["$defs"] = g.defs
	g.constrain()
	body, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

type schemaGenerator struct{ defs schemaObject }

func (g *schemaGenerator) typeSchema(t reflect.Type) schemaObject {
	switch t.Kind() {
	case reflect.Pointer:
		return schemaObject{"anyOf": []any{g.typeSchema(t.Elem()), schemaObject{"type": "null"}}}
	case reflect.Struct:
		name := t.Name()
		if _, exists := g.defs[name]; !exists {
			props := schemaObject{}
			def := schemaObject{"type": "object", "properties": props, "additionalProperties": false}
			g.defs[name] = def
			var required []string
			for _, f := range reflect.VisibleFields(t) {
				if !f.IsExported() {
					continue
				}
				tag := strings.Split(f.Tag.Get("yaml"), ",")
				if tag[0] == "" || tag[0] == "-" {
					continue
				}
				props[tag[0]] = g.typeSchema(f.Type)
				if len(tag) == 1 {
					required = append(required, tag[0])
				}
			}
			if len(required) > 0 {
				def["required"] = required
			}
		}
		return schemaObject{"$ref": "#/$defs/" + name}
	case reflect.Map:
		value := g.typeSchema(t.Elem())
		if t.Elem().Kind() == reflect.String {
			// yaml.v3 accepts scalar environment/build-argument values and
			// converts them to strings. Match that contract in the editor.
			value = schemaObject{"type": []string{"string", "number", "boolean"}}
		}
		return schemaObject{"type": "object", "additionalProperties": value}
	case reflect.Slice:
		item := g.typeSchema(t.Elem())
		if t.Elem().Kind() == reflect.String {
			item = schemaObject{"type": []string{"string", "number", "boolean"}}
		}
		return schemaObject{"type": "array", "items": item}
	case reflect.String:
		return schemaObject{"type": "string"}
	case reflect.Bool:
		return schemaObject{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return schemaObject{"type": "integer"}
	case reflect.Float64:
		return schemaObject{"type": "number"}
	default:
		panic(fmt.Sprintf("manifest schema: unsupported type %s", t))
	}
}

func (g *schemaGenerator) def(name string) schemaObject { return g.defs[name].(schemaObject) }
func (g *schemaGenerator) prop(def, name string) schemaObject {
	return g.def(def)["properties"].(schemaObject)[name].(schemaObject)
}
func (g *schemaGenerator) describe(def, name, description string) {
	g.prop(def, name)["description"] = description
}
func condition(test, constraint schemaObject) schemaObject {
	return schemaObject{"if": test, "then": constraint}
}
func kindIs(kinds ...string) schemaObject {
	return schemaObject{"required": []string{"kind"}, "properties": schemaObject{"kind": schemaObject{"enum": kinds}}}
}
func properties(p schemaObject) schemaObject { return schemaObject{"properties": p} }
func stringsSchema(pattern string) schemaObject {
	return schemaObject{"type": "string", "pattern": pattern}
}
func nonemptyString() schemaObject { return schemaObject{"type": "string", "minLength": 1} }
func portSchema(optional bool) schemaObject {
	port := schemaObject{"type": "integer", "minimum": 1, "maximum": 65535}
	if optional {
		return schemaObject{"anyOf": []any{port, schemaObject{"const": 0}}}
	}
	return port
}

func (g *schemaGenerator) constrain() {
	g.prop("Manifest", "app")["pattern"] = namePattern.String()
	g.prop("Manifest", "app")["not"] = schemaObject{"enum": sortedKeys(reservedApps)}
	workloads := g.prop("Manifest", "workloads")
	workloads["minProperties"] = 1
	workloads["propertyNames"] = stringsSchema(namePattern.String())
	g.describe("Manifest", "description", "One line about what this app is for.")
	g.describe("Manifest", "owner", "Who owns the app, such as personal or a business name.")
	g.describe("Manifest", "repo", "Where the app's source lives.")
	g.describe("Volume", "backup", "false leaves the volume out of backups, for caches and copies the app rebuilds or fetches again; a restore, drill or move creates it empty. Default true.")
	g.prop("ReleasePolicy", "data_compatibility")["enum"] = []string{DataBackwardCompatible, DataRestoreRequired}
	g.describe("ReleasePolicy", "data_compatibility", "Whether older code can use data changed by release jobs; restore-required blocks rollback until a compatible checkpoint is restored.")

	w := g.def("Workload")
	g.prop("Workload", "kind")["enum"] = []Kind{Web, Static, Worker, Cron, Release}
	g.describe("Workload", "image", "An existing container image; give image or build for non-static workloads.")
	g.describe("Workload", "build", "Build an image from the source; image and build are alternatives.")
	g.describe("Workload", "dir", "A static workload's directory inside the source.")
	g.describe("Workload", "port", "The container port a web workload listens on.")
	g.describe("Workload", "schedule", "Five-field cron schedule in UTC; only cron workloads use it.")
	g.describe("Workload", "timeout", "Go duration such as 10m; only cron and release workloads use it.")
	g.describe("Workload", "singleton", "Stop the old container before starting the new one; required for published ports.")
	g.describe("Workload", "grace", "Graceful stop duration, from 1s to 10m. Default 10s.")
	g.prop("Workload", "dir")["pattern"] = `^(?!/)(?!.*\.\.).*$`
	g.prop("Workload", "aliases")["items"] = stringsSchema(namePattern.String())
	g.prop("Workload", "tmpfs")["items"] = stringsSchema(`^/`)
	g.prop("Workload", "capabilities")["items"] = stringsSchema(`^(?:[Cc][Aa][Pp]_)?[A-Za-z][A-Za-z0-9_]*$`)
	g.prop("Workload", "user")["anyOf"] = []any{stringsSchema(userPattern.String()), schemaObject{"const": ""}}
	delete(g.prop("Workload", "user"), "type")
	for _, def := range []string{"Workload", "Postgres"} {
		g.prop(def, "env")["propertyNames"] = stringsSchema(envPattern.String())
		g.prop(def, "secrets")["items"] = stringsSchema(envPattern.String())
	}
	imageOrBuild := schemaObject{"oneOf": []any{
		schemaObject{"required": []string{"image"}, "properties": schemaObject{"image": nonemptyString(), "build": schemaObject{"type": "null"}}},
		schemaObject{"required": []string{"build"}, "properties": schemaObject{"build": schemaObject{"type": "object"}, "image": schemaObject{"const": ""}}},
	}}
	w["allOf"] = []any{
		condition(kindIs(string(Web), string(Worker), string(Cron), string(Release)), imageOrBuild),
		condition(kindIs(string(Web)), schemaObject{"required": []string{"port", "routes"}, "properties": schemaObject{"port": portSchema(false), "routes": schemaObject{"minItems": 1}}}),
		condition(kindIs(string(Static)), schemaObject{"required": []string{"dir", "routes"}, "properties": schemaObject{"dir": nonemptyString(), "routes": schemaObject{"minItems": 1, "items": properties(schemaObject{"port": schemaObject{"const": 0}})}, "image": schemaObject{"const": ""}, "build": schemaObject{"type": "null"}, "port": schemaObject{"const": 0}}}),
		condition(kindIs(string(Web), string(Worker), string(Cron), string(Release)), properties(schemaObject{"dir": schemaObject{"const": ""}})),
		condition(kindIs(string(Worker), string(Cron), string(Release)), properties(schemaObject{"routes": schemaObject{"maxItems": 0}})),
		condition(kindIs(string(Cron)), schemaObject{"required": []string{"schedule"}, "properties": schemaObject{"schedule": nonemptyString(), "port": schemaObject{"const": 0}}}),
		condition(kindIs(string(Release)), properties(schemaObject{"port": schemaObject{"const": 0}})),
		condition(kindIs(string(Web), string(Static), string(Worker), string(Release)), properties(schemaObject{"schedule": schemaObject{"const": ""}})),
		condition(kindIs(string(Web), string(Static), string(Worker)), properties(schemaObject{"timeout": schemaObject{"const": ""}})),
		condition(kindIs(string(Web), string(Static), string(Worker), string(Cron)), properties(schemaObject{"order": schemaObject{"const": 0}})),
		condition(kindIs(string(Static), string(Cron), string(Release)), properties(schemaObject{"singleton": schemaObject{"const": false}})),
		condition(schemaObject{"required": []string{"ports"}, "properties": schemaObject{"ports": schemaObject{"minItems": 1}}}, schemaObject{"required": []string{"singleton"}, "properties": schemaObject{"singleton": schemaObject{"const": true}, "kind": schemaObject{"enum": []Kind{Web, Worker}}}}),
		condition(schemaObject{"required": []string{"privileged"}, "properties": schemaObject{"privileged": schemaObject{"const": true}}}, properties(schemaObject{"capabilities": schemaObject{"maxItems": 0}})),
	}
	g.prop("Build", "context")["pattern"] = `^(?!/)(?!.*\.\.).*$`
	g.describe("Build", "context", "Build directory inside the source. Default .")
	g.describe("Build", "dockerfile", "Dockerfile relative to the build context. Default Dockerfile.")
	g.describe("Build", "target", "A named stage of a multi-stage Dockerfile.")
	g.prop("PublishedPort", "port")["minimum"] = 1
	g.prop("PublishedPort", "port")["maximum"] = 65535
	g.prop("PublishedPort", "host_port")["anyOf"] = []any{portSchema(false), schemaObject{"const": 0}}
	g.prop("PublishedPort", "protocol")["enum"] = []string{"", "tcp", "udp"}
	g.describe("PublishedPort", "address", "Machine IP to bind; omitted means every address. Docker publishes past ufw.")
	g.prop("Route", "host")["pattern"] = hostPattern.String()
	g.prop("Route", "path")["pattern"] = `^(?:/[^*]*|)$`
	g.prop("Route", "port")["anyOf"] = []any{portSchema(false), schemaObject{"const": 0}}
	g.prop("Route", "dns")["enum"] = []DNSMode{DNSManual, DNSDirect, DNSProxied}
	g.prop("Route", "auth")["enum"] = []AuthMode{AuthNone, AuthLoom}
	g.describe("Route", "dns", "direct or proxied manages Cloudflare DNS; omitted leaves DNS alone.")
	g.describe("Route", "auth", "loom requires a signed-in Loom session; omitted leaves the route open.")
	g.prop("Route", "origin_pull")["enum"] = []OriginPullMode{OriginPullOptional, OriginPullRequired}
	g.describe("Route", "origin_pull", "Check the client certificate Cloudflare presents, minted with helios edge origin-pull mint: optional checks one that is presented, required refuses connections without one. Needs dns: proxied and the same value on every route to the host; omitted takes any connection.")
	g.def("Route")["allOf"] = []any{condition(schemaObject{"required": []string{"origin_pull"}}, schemaObject{"required": []string{"dns"}, "properties": schemaObject{"dns": schemaObject{"const": DNSProxied}}})}
	g.prop("Health", "path")["pattern"] = `^(?:/.*|)$`
	g.def("Health")["allOf"] = []any{condition(schemaObject{"required": []string{"command"}, "properties": schemaObject{"command": schemaObject{"minItems": 1}}}, properties(schemaObject{"path": schemaObject{"const": ""}}))}
	g.describe("Health", "timeout", "Positive Go duration such as 90s. Default 60s.")
	g.prop("Health", "command")["items"] = schemaObject{"type": []string{"string", "number", "boolean"}, "minLength": 1}
	g.prop("Resources", "memory")["pattern"] = `^(?:0*[1-9][0-9]*[kmg]|)$`
	g.prop("Resources", "cpus")["minimum"] = 0
	g.prop("Resources", "cpus")["maximum"] = 64
	g.prop("Resources", "pids")["anyOf"] = []any{schemaObject{"const": 0}, schemaObject{"minimum": 16, "maximum": 1 << 20}}
	g.describe("Resources", "memory", "Positive container memory ceiling in binary k, m or g units, such as 512m or 2g, within signed 64-bit bytes. Default 2g.")
	g.prop("Mount", "path")["pattern"] = `^/`
	g.describe("Mount", "volume", "A volume declared under this app's data.volumes.")
	g.prop("Data", "volumes")["propertyNames"] = schemaObject{"allOf": []any{stringsSchema(namePattern.String()), schemaObject{"not": schemaObject{"enum": []string{DatabaseVolume, ObjectsVolume}}}}}
	g.prop("Postgres", "version")["type"] = []string{"string", "integer"}
	g.prop("Postgres", "version")["enum"] = []any{"", "15", "16", "17", "18", 15, 16, 17, 18}
	g.describe("Postgres", "version", "Supported major version, 15 through 18. Default 16.")
	for _, field := range []string{"user", "database"} {
		g.prop("Postgres", field)["pattern"] = `^(?:[a-z_][a-z0-9_]{0,62}|)$`
	}
	g.prop("Postgres", "init")["pattern"] = `^(?!/)(?!.*\.\.).*$`
	g.describe("Postgres", "init", "File or directory of .sql, .sql.gz or .sh first-run scripts inside the source.")
	for _, field := range []string{"generate", "derive"} {
		g.prop("Secrets", field)["propertyNames"] = stringsSchema(envPattern.String())
	}
	g.prop("Secrets", "generate")["additionalProperties"] = stringsSchema(`^(?:(?:hex|base64|base64url):(?:[89]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-6])|value:[^\r\n\u0000]+)$`)
	g.describe("Secrets", "derive", "Templates may refer to {NAME}, {sha256:NAME}, {postgres} and {objects}.")
	for _, field := range []string{"daily", "weekly", "monthly"} {
		g.prop("Keep", field)["minimum"] = 0
	}
	g.def("Keep")["anyOf"] = []any{
		schemaObject{"required": []string{"daily"}, "properties": schemaObject{"daily": schemaObject{"minimum": 1}}},
		schemaObject{"required": []string{"weekly"}, "properties": schemaObject{"weekly": schemaObject{"minimum": 1}}},
		schemaObject{"required": []string{"monthly"}, "properties": schemaObject{"monthly": schemaObject{"minimum": 1}}},
	}
	g.prop("Verify", "sql")["pattern"] = `\S`
	g.prop("Verify", "at_least")["minimum"] = 0
	g.describe("Backup", "schedule", "Five-field cron schedule in UTC. Default "+DefaultBackupSchedule)
	g.describe("Backup", "drill", "Five-field cron schedule in UTC. Default "+DefaultDrillSchedule)
	g.describe("Backup", "off", "Opt out of backups when the app's data is disposable.")
	g.prop("Check", "url")["pattern"] = `^https?://[^/?#@]+(?:[/?#]|$)`
	g.prop("Check", "context")["enum"] = []string{"", "application", "edge"}
	g.describe("Check", "context", "application probes the candidate container; edge probes the public route. Omitted runs the applicable checks in both phases.")
	headers := g.prop("Check", "headers_from_secrets")
	headers["additionalProperties"] = stringsSchema(envPattern.String())
	headers["propertyNames"] = stringsSchema("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	// Do not duplicate routing-header policy in the generator: derive the
	// prohibited names from the authoritative validator over known names.
	var forbidden []string
	for _, header := range []string{"host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-authenticate", "keep-alive", "te", "trailer", "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "x-forwarded-uri", "x-forwarded-method", "x-real-ip"} {
		if !ValidCheckHeader(header) {
			forbidden = append(forbidden, caseFoldPattern(header))
		}
	}
	headers["propertyNames"] = schemaObject{"allOf": []any{stringsSchema("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"), schemaObject{"not": schemaObject{"pattern": "^(?:" + strings.Join(forbidden, "|") + ")$"}}}}
	g.describe("Check", "headers_from_secrets", "Request header names mapped to existing UPPER_CASE app secret names. Requires context: edge and an HTTPS URL; values never enter the manifest.")
	g.def("Check")["allOf"] = []any{condition(schemaObject{"required": []string{"headers_from_secrets"}, "properties": schemaObject{"headers_from_secrets": schemaObject{"minProperties": 1}}}, schemaObject{"required": []string{"context"}, "properties": schemaObject{"context": schemaObject{"const": "edge"}, "url": schemaObject{"pattern": "^https://"}}})}
	g.prop("Check", "status")["minimum"] = 0
	g.prop("Check", "status")["maximum"] = 599
	g.describe("Check", "within", "Positive Go duration such as 5s, limiting acceptable response time.")
	g.prop("Preview", "of")["pattern"] = namePattern.String()
	g.prop("Preview", "branch")["pattern"] = `^[^\r\n]*\S[^\r\n]*$`
	g.def("Manifest")["allOf"] = []any{condition(schemaObject{"required": []string{"release"}, "properties": schemaObject{"release": schemaObject{"type": "object"}}}, properties(schemaObject{"workloads": schemaObject{"not": schemaObject{"additionalProperties": schemaObject{"properties": schemaObject{"kind": schemaObject{"not": schemaObject{"const": Release}}}}}}})), condition(schemaObject{"required": []string{"preview"}, "properties": schemaObject{"preview": schemaObject{"type": "object"}}}, properties(schemaObject{"workloads": schemaObject{"additionalProperties": properties(schemaObject{"ports": schemaObject{"maxItems": 0}, "routes": schemaObject{"items": schemaObject{"required": []string{"auth"}, "properties": schemaObject{"auth": schemaObject{"const": AuthLoom}}}}})}}))}
}

// caseFoldPattern is an ECMAScript-compatible case-insensitive literal.
func caseFoldPattern(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' {
			fmt.Fprintf(&b, "[%c%c]", ch, ch-'a'+'A')
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}
