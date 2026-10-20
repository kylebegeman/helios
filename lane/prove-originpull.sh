#!/usr/bin/env bash
# Authenticated origin pulls on the lane. A proxied host takes any
# connection until its routes ask for origin_pull. A deploy that requires it
# before the edge trusts a CA is refused at the plan. Once helios edge
# origin-pull mint has made the leaf Cloudflare presents, optional checks a
# certificate that is presented and the edge's access log names it, and
# required takes only connections that
# present that leaf: port 80 redirects, a Host that differs from the
# handshake's name gets 421, and a dns: direct host beside it is served
# exactly as before. forget won't take a required host's last CA, minting
# again keeps the old CA until it is forgotten, and taking origin_pull off
# puts the edge back as it was.
#
# The guest has no public address, name or certificate, so the proof
# brings its own for the run: a documentation address on a dummy interface
# for the records to name, the Cloudflare stand-in (fakeflare) serving
# lane.test, an /etc/hosts line so the direct host resolves here, and a
# throwaway CA, trusted on the guest, whose certificates are seeded into the
# edge's storage. Every request is made on the guest, to 127.0.0.1, playing
# Cloudflare with the minted leaf. Cloudflare presenting it is the one step
# left to a person: README.md, Authenticated origin pulls, says how.
#
# Needs the lane after prove-m2.sh, without the site app, a cloudflare
# integration or the stand-in's container.
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lane/common.sh
. "$here/common.sh"
run() { ssh "${ssh_opts[@]}" "$box" "$@"; }
put() { scp -q "${scp_opts[@]}" "$1" "$box:$2"; }
quiet() { grep -v '^  \.\.\.  ' || true; }
fail() { echo "ORIGIN PULL NOT proven: $*" >&2; exit 1; }

op=op.lane.test         # the host that takes origin pulls
direct=direct.lane.test # a dns: direct host beside it, which must not change
op_re=${op//./\\.}
address=192.0.2.10      # the machine's public address for the run, from the documentation range
remote_work="/var/lib/bedrock/lane-originpull/$LANE_ID"
storage=/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory
work=$(mktemp -d "${TMPDIR:-/tmp}/bedrock-originpull.XXXXXX")
started=false

# undo puts the guest back as the proof found it. A step with nothing to do
# is skipped, so it also clears what a run that was killed left behind.
undo() {
  run "sh -s -- '$remote_work' $op $direct $address $storage" <<'UNDO' || true
work=$1 op=$2 direct=$3 address=$4 storage=$5
bedrock remove site --data --yes >/dev/null 2>&1 || true
bedrock edge origin-pull forget "$op" >/dev/null 2>&1 || true
bedrock integration remove cloudflare >/dev/null 2>&1 || true
docker rm -f lane-cloudflare >/dev/null 2>&1 || true
docker run --rm -v bedrock-edge-data:/data alpine:3.21 rm -rf "$storage/$op" "$storage/$direct" >/dev/null 2>&1 || true
ip link del lane-op0 >/dev/null 2>&1 || true
ip addr del "$address/32" dev lo >/dev/null 2>&1 || true
sed -i '/# bedrock-lane-originpull$/d' /etc/hosts || true
if [ -e /usr/local/share/ca-certificates/bedrock-lane-originpull.crt ]; then
  rm -f /usr/local/share/ca-certificates/bedrock-lane-originpull.crt
  update-ca-certificates >/dev/null 2>&1 || true
  systemctl restart bedrock || true
fi
rm -rf "$work"
UNDO
}
cleanup() {
  if [[ "$started" == true ]]; then undo; fi
  rm -rf "$work"
}
trap cleanup EXIT

# expect <what> <pattern> <got> shows what a request got, and fails unless
# it matches the whole pattern.
expect() {
  echo "-- $1: $3"
  [[ "$3" =~ ^($2)$ ]] || fail "$1 gave $3, not $2"
}
# expect_refusal <regex> <cmd...> fails unless the command fails saying so.
expect_refusal() {
  local message=$1
  shift
  if "$@" >"$work/refusal.log" 2>&1; then
    cat "$work/refusal.log" >&2
    fail "expected a refusal ($message)"
  fi
  grep -E "refused|$message" "$work/refusal.log" | quiet | head -3 || true
  grep -qE "$message" "$work/refusal.log" || { cat "$work/refusal.log" >&2; fail "the refusal didn't say $message"; }
}
# presenting <name> is the curl arguments that present the client
# certificate <name>.crt and its key from the guest's work directory.
presenting() { printf '%s' "--cert '$remote_work/$1.crt' --key '$remote_work/$1.key'"; }
# get <sni> [curl args] prints the status of an HTTPS request the guest
# makes to its edge under that name, or 000 when the connection fails.
get() {
  local sni=$1
  shift
  run "curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve $sni:443:127.0.0.1 --cacert '$remote_work/edge-ca.crt' $* https://$sni/ || true"
}
# nosni [curl args] asks for op by address, with no name in the handshake.
nosni() { run "curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: $op' $* https://127.0.0.1/ || true"; }
# http80 <host> prints the status and redirect of a plain HTTP request.
http80() { run "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 -H 'Host: $1' http://127.0.0.1/ || true" | sed 's/ *$//'; }
# server prints the edge's HTTP server as Caddy holds it.
server() { run 'curl -sf --unix-socket /var/lib/bedrock/edge/run/caddy.sock http://localhost/config/apps/http/servers/bedrock'; }
# routes_of <server json> <host> prints the host's routes, without the
# container each one dials, which every deploy renames.
routes_of() {
  python3 - "$1" "$2" <<'PY'
import json, sys
def blank(v):
    if isinstance(v, dict):
        return {k: ("" if k == "dial" else blank(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [blank(x) for x in v]
    return v
server = json.load(open(sys.argv[1]))
print(json.dumps([blank(r) for r in server["routes"] if any(sys.argv[2] in m.get("host", []) for m in r.get("match", []))], indent=1, sort_keys=True))
PY
}
# same_routes <server json> <host> fails unless the host's routes are what
# they were before any origin_pull.
same_routes() {
  [[ "$(routes_of "$1" "$2")" == "$(routes_of "$work/baseline.json" "$2")" ]] && return
  diff <(routes_of "$work/baseline.json" "$2") <(routes_of "$1" "$2") >&2 || true
  fail "$2's routes changed"
}
# no_policy <server json> fails unless the edge asks no connection for a
# client certificate, and leaves strict SNI to Caddy.
no_policy() {
  python3 - "$1" <<'PY' || fail "the edge still has a TLS connection policy"
import json, sys
server = json.load(open(sys.argv[1]))
left = {k: server[k] for k in ("tls_connection_policies", "strict_sni_host") if k in server}
assert not left, left
PY
}
# policy <server json> <caddy mode> fails unless op alone has a TLS
# connection policy, checking client certificates as mode says against one
# inline CA, with strict SNI on and op alone served over HTTPS only.
policy() {
  python3 - "$1" "$op" "$direct" "$2" <<'PY' || fail "the edge's configuration isn't $2 for $op"
import json, sys
server, op, direct, mode = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4]
policies = server.get("tls_connection_policies") or []
assert len(policies) == 2 and policies[-1] == {}, policies
mine = policies[0]
assert mine.get("match") == {"sni": [op]}, mine
auth = mine["client_authentication"]
assert auth["mode"] == mode and auth["ca"]["provider"] == "inline" and len(auth["ca"]["trusted_ca_certs"]) == 1, auth
assert server.get("strict_sni_host") is True, "strict_sni_host isn't on"
for route in server["routes"]:
    for match in route.get("match", []):
        if op in match.get("host", []):
            assert match.get("protocol") == "https", match
        if direct in match.get("host", []):
            assert "protocol" not in match, match
print(f"-- the edge: {mode} for {op} alone, strict SNI on, {op} over HTTPS only")
PY
}
site_revision() { run 'bedrock ls --json' | python3 -c 'import json,sys; print(next((a["revision"] for a in json.load(sys.stdin)["apps"] or [] if a["name"]=="site"), ""))'; }
# cas prints the fingerprints of the CAs op trusts, as list --json shows them.
cas() { run 'bedrock edge origin-pull list --json' | python3 -c 'import json,sys; [print(ca["fingerprint"]) for r in json.load(sys.stdin) if r["host"]==sys.argv[1] for ca in r["cas"]]' "$op"; }
# records prints the stand-in's records as name, content, and how traffic
# reaches it.
records() {
  run "curl -s -H \"Authorization: Bearer \$(cat '$remote_work/cloudflare-token')\" 'http://127.0.0.1:8788/client/v4/zones/zone-lane-test/dns_records?per_page=100'" \
    | python3 -c 'import json,sys; [print(r["name"], r["content"], "proxied" if r.get("proxied") else "direct") for r in json.load(sys.stdin)["result"]]'
}
# manifest [mode] writes the site's manifest: op behind Cloudflare's proxy,
# with origin_pull when a mode is given, and the direct host beside it.
manifest() {
  local origin_pull=""
  [[ -z "${1:-}" ]] || origin_pull=$'\n'"        origin_pull: $1"
  run "cat > '$remote_work/site/helios.yaml'" <<YAML
app: site
description: The lane's static fixture, behind an edge that takes origin pulls
owner: personal
workloads:
  pages:
    kind: static
    dir: public
    routes:
      - host: $op
        dns: proxied$origin_pull
      - host: $direct
        dns: direct
YAML
}
# deploy <what> deploys the site as its manifest stands.
deploy() {
  if ! run "bedrock deploy '$remote_work/site' --yes" >"$work/deploy.log" 2>&1; then
    tail -20 "$work/deploy.log" >&2
    fail "the deploy $1 failed"
  fi
  grep -E "proxy|points here|lane\.test: |succeeded" "$work/deploy.log" | quiet | head -6 || true
}
# mint <name> mints op's leaf into <name>.pem on the guest, and splits it
# into the certificate and the key Cloudflare's form asks for.
mint() {
  run "bedrock edge origin-pull mint $op --out '$remote_work/$1.pem'" >"$work/mint.log" 2>&1 || { cat "$work/mint.log" >&2; fail "minting $1 failed"; }
  cat "$work/mint.log"
  run "cd '$remote_work' && openssl x509 -in $1.pem -out $1.crt && openssl pkey -in $1.pem -out $1.key" \
    || fail "$1.pem doesn't hold a certificate and its key"
}

echo "== build and install"
(cd "$here/.." && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o "bin/bedrock-linux-$LANE_ARCH" ./cmd/helios \
  && CGO_ENABLED=0 GOOS=linux GOARCH="$LANE_ARCH" go build -trimpath -o "bin/fakeflare-linux-$LANE_ARCH" ./lane/fixtures/fakeflare)
put "$here/../bin/bedrock-linux-$LANE_ARCH" /usr/local/bin/bedrock.new
run 'chmod 755 /usr/local/bin/bedrock.new && mv -f /usr/local/bin/bedrock.new /usr/local/bin/bedrock && bedrock daemon install >/dev/null && bedrock version'
run 'bedrock host reconcile --yes' >"$work/reconcile.log" 2>&1 || { tail -5 "$work/reconcile.log" >&2; fail "bedrock host reconcile failed; run prove-m2.sh first"; }
quiet <"$work/reconcile.log" | tail -1

echo "== the guest has no site, cloudflare integration or stand-in of its own"
if run "test -e '$remote_work/started'"; then
  echo "-- a run that was stopped left $remote_work behind; putting the guest back first"
  undo
fi
[[ -z "$(site_revision)" ]] || fail "site is deployed; remove it with bedrock remove site --data --yes, then run the proof again"
if run 'bedrock integration list --json' | python3 -c 'import json,sys; sys.exit(0 if any(i["name"]=="cloudflare" and i.get("set") for i in json.load(sys.stdin)["integrations"]) else 1)'; then
  fail "a cloudflare integration is set, and the proof sets its own; remove it with bedrock integration remove cloudflare, then run the proof again"
fi
[[ -z "$(run 'docker ps -aq --filter name=^lane-cloudflare$')" ]] || fail "a lane-cloudflare container exists; remove it with docker rm -f lane-cloudflare, then run the proof again"
run "install -d -m 700 '$remote_work' && touch '$remote_work/started'"
started=true

echo "== $address stands in for the machine's public address, and $direct resolves to it"
run "sh -s -- $address $direct" <<'ADDRESS' || fail "the guest couldn't take $address"
set -eu
if ip link add lane-op0 type dummy 2>/dev/null; then
  ip addr add "$1/32" dev lane-op0
  ip link set lane-op0 up
else
  ip addr add "$1/32" dev lo scope global
fi
printf '%s %s # bedrock-lane-originpull\n' "$1" "$2" >>/etc/hosts
ip -o addr show scope global | grep -F "inet $1/32" || { echo "$1 isn't a global address" >&2; exit 1; }
ADDRESS

echo "== the Cloudflare stand-in serves lane.test; its token stays on the guest"
put "$here/../bin/fakeflare-linux-$LANE_ARCH" "$remote_work/fakeflare"
run "sh -s -- '$remote_work'" <<'FAKEFLARE' || fail "the Cloudflare stand-in didn't start"
set -eu
chmod 755 "$1/fakeflare"
head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$1/cloudflare-token"
docker run -d --name lane-cloudflare -p 127.0.0.1:8788:8788 -e FAKEFLARE_TOKEN="$(cat "$1/cloudflare-token")" -e FAKEFLARE_ZONES=lane.test -v "$1/fakeflare:/fakeflare:ro" alpine:3.21 /fakeflare >/dev/null
for _ in $(seq 1 15); do curl -s -o /dev/null http://127.0.0.1:8788/ && break; sleep 1; done
printf 'token=%s\napi=http://127.0.0.1:8788/client/v4\n' "$(cat "$1/cloudflare-token")" | bedrock integration set cloudflare
FAKEFLARE

echo "== certificates for both hosts from a CA the guest trusts for the run, seeded into the edge's storage"
run "sh -s -- '$remote_work' $op $direct $storage" <<'CERTS' || fail "the lane's certificates couldn't be made"
set -eu
umask 077
cd "$1"
op=$2 direct=$3 storage=$4
cat >ca.cnf <<'CNF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3
[dn]
CN = lane
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
CNF
# ca <name> <common name> <days> makes a CA.
ca() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -days "$3" -config ca.cnf -out "$1.crt"
}
# leaf <name> <common name> <ca> <days> <extensions> makes a certificate
# the CA signs.
leaf() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -config ca.cnf -out "$1.csr"
  printf '%b' "$5" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" -CAcreateserial -days "$4" -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}
ca edge-ca "helios lane edge CA" 31
for h in "$op" "$direct"; do
  leaf "$h" "$h" edge-ca 30 "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:$h\nauthorityKeyIdentifier = keyid\n"
  printf '{"sans":["%s"],"issuer_data":{}}\n' "$h" >"$h.json"
  docker run --rm -v bedrock-edge-data:/data -v "$PWD:/seed:ro" alpine:3.21 \
    sh -c 'mkdir -p "$1/$2" && cp "/seed/$2.crt" "/seed/$2.key" "/seed/$2.json" "$1/$2/"' seed "$storage" "$h"
  openssl x509 -in "$h.crt" -noout -subject -enddate
done
# A client certificate for op from a CA nobody trusts, as anyone could make.
ca foreign-ca "a CA nobody trusts for $op" 2
leaf foreign "$op" foreign-ca 2 "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth\nauthorityKeyIdentifier = keyid\n"
install -m 644 edge-ca.crt /usr/local/share/ca-certificates/bedrock-lane-originpull.crt
update-ca-certificates >/dev/null
# The daemon reads the trusted CAs once, when it starts.
systemctl restart bedrock
for _ in $(seq 1 30); do bedrock daemon status >/dev/null 2>&1 && break; sleep 1; done
bedrock daemon status
CERTS
(cd "$here/fixtures" && COPYFILE_DISABLE=1 tar czf - site) | run "tar xzf - -C '$remote_work' 2>/dev/null"

echo "== before origin_pull: op is proxied, direct is direct, and the edge takes any connection"
manifest
deploy "of the site without origin_pull"
zone=$(records)
echo "$zone"
grep -qx "$op $address proxied" <<<"$zone" || fail "$op has no proxied record naming $address"
grep -qx "$direct $address direct" <<<"$zone" || fail "$direct has no direct record naming $address"
caddy=$(run 'docker exec bedrock-edge caddy version')
echo "-- caddy $caddy"
run 'image=$(docker inspect -f "{{.Image}}" bedrock-edge); echo "-- edge image $image $(docker image inspect -f "{{range .RepoDigests}}{{.}} {{end}}" "$image")"'
if ! [[ "$caddy" =~ ^v2\.([0-9]+)\. ]] || (( BASH_REMATCH[1] < 8 )); then
  fail "the edge runs Caddy $caddy, and origin pulls need an inline CA pool, which came in 2.8"
fi
run 'docker exec bedrock-edge caddy list-modules | grep -qx tls.ca_pool.source.inline' || fail "the edge's Caddy has no tls.ca_pool.source.inline module"
server >"$work/baseline.json" || fail "the edge's configuration couldn't be read"
no_policy "$work/baseline.json"
expect "$op, no certificate" 200 "$(get "$op")"
expect "$direct" 200 "$(get "$direct")"
expect "$op's Host under $direct's name" 200 "$(get "$direct" "-H 'Host: $op'")"
op80=$(http80 "$op")
expect "port 80 for $op" "200|308 https://$op_re/" "$op80"
direct80=$(http80 "$direct")
echo "-- port 80 for $direct: $direct80"

echo "== requiring origin pull before the edge trusts a CA is refused at the plan"
before=$(site_revision)
manifest required
expect_refusal "trusts no CA for it.*origin-pull mint $op_re" run "bedrock deploy '$remote_work/site' --yes"
[[ "$(site_revision)" == "$before" ]] || fail "a refused deploy changed site from $before to $(site_revision)"

echo "== mint: the edge trusts a new CA, and the leaf and its key go to a new file"
mint op-leaf
run "sh -s -- '$remote_work' $op" <<'LEAF' || fail "op-leaf.pem isn't the leaf Cloudflare presents"
set -eu
cd "$1"
[ "$(stat -c %a op-leaf.pem)" = 600 ] || { echo "op-leaf.pem is mode $(stat -c %a op-leaf.pem), not 600" >&2; exit 1; }
openssl x509 -in op-leaf.crt -noout -subject -issuer -enddate
text=$(openssl x509 -in op-leaf.crt -noout -text)
echo "$text" | grep -q "TLS Web Client Authentication" || { echo "the leaf isn't for client authentication" >&2; exit 1; }
echo "$text" | grep -q "CA:FALSE" || { echo "the leaf isn't marked as no CA" >&2; exit 1; }
echo "$text" | grep -q "Public-Key: (2048 bit)" || { echo "the leaf's key isn't RSA-2048" >&2; exit 1; }
openssl x509 -in op-leaf.crt -noout -issuer | grep -q "helios origin pull CA for $2" || { echo "the leaf's issuer isn't $2's CA" >&2; exit 1; }
openssl x509 -in op-leaf.crt -noout -subject | grep -q "CN *= *$2" || { echo "the leaf doesn't name $2" >&2; exit 1; }
[ "$(openssl x509 -in op-leaf.crt -noout -pubkey)" = "$(openssl pkey -in op-leaf.key -pubout)" ] || { echo "the key isn't the leaf's" >&2; exit 1; }
openssl x509 -in op-leaf.crt -noout -checkend $((360 * 86400)) >/dev/null || { echo "the leaf runs out within 360 days" >&2; exit 1; }
if openssl x509 -in op-leaf.crt -noout -checkend $((367 * 86400)) >/dev/null; then echo "the leaf lasts more than a year" >&2; exit 1; fi
LEAF
leaf_sum=$(run "sha256sum '$remote_work/op-leaf.pem'")
expect_refusal "already exists" run "bedrock edge origin-pull mint $op --out '$remote_work/op-leaf.pem'"
[[ "$(run "sha256sum '$remote_work/op-leaf.pem'")" == "$leaf_sum" ]] || fail "a refused mint changed op-leaf.pem"
[[ "$(cas | grep -c . || true)" == 1 ]] || fail "a refused mint trusted another CA"

echo "== optional: a certificate is checked when one is presented, and a connection without one still succeeds"
manifest optional
deploy "with origin_pull: optional"
server >"$work/optional.json"
policy "$work/optional.json" verify_if_given
expect "$op, no certificate" 200 "$(get "$op")"
expect "$op, the minted leaf" 200 "$(get "$op" "$(presenting op-leaf)")"
# The edge's access log is how README.md tells a person, under optional,
# that Cloudflare presents the leaf: a request whose certificate the edge
# checked is logged with its common name.
logged=$(run "docker logs --since 10m bedrock-edge 2>&1 | grep -cF '\"client_common_name\":\"$op\"' || true")
[[ "$logged" =~ ^[1-9][0-9]*$ ]] || fail "the edge's access log doesn't name the certificate a request to $op presented"
echo "-- the edge's access log names the leaf's common name on $logged request(s)"
expect "$op, a leaf from a CA nobody trusts" 000 "$(get "$op" "$(presenting foreign)")"
expect "port 80 for $op" "308 https://$op_re/" "$(http80 "$op")"
expect "$op's Host under $direct's name" 421 "$(get "$direct" "-H 'Host: $op'")"
expect "$direct" 200 "$(get "$direct")"

echo "== required: only the minted leaf gets through"
manifest required
deploy "with origin_pull: required"
server >"$work/required.json"
policy "$work/required.json" require_and_verify
expect "$op, no certificate" 000 "$(get "$op")"
expect "$op, a leaf from a CA nobody trusts" 000 "$(get "$op" "$(presenting foreign)")"
expect "$op, the minted leaf" 200 "$(get "$op" "$(presenting op-leaf)")"
body=$(run "curl -s --max-time 10 --resolve $op:443:127.0.0.1 --cacert '$remote_work/edge-ca.crt' $(presenting op-leaf) https://$op/ || true")
[[ "$body" == *"A static site served by helios"* ]] || fail "the minted leaf didn't get the site's page"
expect "port 80 for $op" "308 https://$op_re/" "$(http80 "$op")"
expect "$op by address, no name in the handshake" "000|421" "$(nosni)"
expect "$op by address, no name in the handshake, the minted leaf" "000|421" "$(nosni "$(presenting op-leaf)")"
expect "$op's Host under $direct's name, the minted leaf" 421 "$(get "$direct" "-H 'Host: $op' $(presenting op-leaf)")"
expect "$direct" 200 "$(get "$direct")"
expect "port 80 for $direct, as before" "${direct80//./\\.}" "$(http80 "$direct")"
same_routes "$work/required.json" "$direct"
echo "-- $direct's routes are as they were"
names=$(run "timeout 10 openssl s_client -connect 127.0.0.1:443 -servername $op </dev/null 2>/dev/null | grep -A2 'Acceptable client certificate CA names' || true")
echo "-- the CAs the edge names in its request: ${names:-none it said}"
echo "-- Alt-Svc: $(run "curl -sI --max-time 10 --resolve $op:443:127.0.0.1 --cacert '$remote_work/edge-ca.crt' $(presenting op-leaf) https://$op/ | grep -i '^alt-svc' | tr -d '\r' || true")"
curl_version=$(run 'curl --version')
if grep -q 'HTTP3' <<<"$curl_version"; then
  expect "$op over HTTP/3, no certificate" 000 "$(get "$op" --http3-only)"
  expect "$op over HTTP/3, the minted leaf" 200 "$(get "$op" "--http3-only $(presenting op-leaf)")"
else
  echo "-- HTTP/3 skipped: the guest's curl doesn't speak it ($(head -1 <<<"$curl_version"))"
fi

echo "== list shows the host, its mode and the CA, which the leaf chains to and the edge holds"
run 'bedrock edge origin-pull list'
run 'bedrock edge origin-pull list --json' >"$work/list.json"
fingerprint=$(python3 - "$work/list.json" "$op" "$work/listed-ca.pem" <<'PY'
import json, sys
rows = [r for r in json.load(open(sys.argv[1])) if r["host"] == sys.argv[2]]
assert len(rows) == 1, rows
row = rows[0]
assert row["mode"] == "required" and len(row["cas"]) == 1 and row["valid_cas"] == 1, row
ca = row["cas"][0]
assert ca["fingerprint"].startswith("sha256:"), ca
open(sys.argv[3], "w").write(ca["ca_pem"])
print(ca["fingerprint"])
PY
) || fail "list --json doesn't show $op as required with one CA"
put "$work/listed-ca.pem" "$remote_work/listed-ca.pem"
run "cd '$remote_work' && openssl verify -CAfile listed-ca.pem op-leaf.crt" || fail "the leaf doesn't chain to the CA list shows"
der=$(run "openssl x509 -in '$remote_work/listed-ca.pem' -outform der | sha256sum" | awk '{print $1}')
[[ "$fingerprint" == "sha256:$der" ]] || fail "list's fingerprint $fingerprint isn't the CA's sha256:$der"
python3 - "$work/required.json" "$work/listed-ca.pem" <<'PY' || fail "the edge doesn't check against the CA list shows"
import base64, json, ssl, sys
server = json.load(open(sys.argv[1]))
der = base64.b64encode(ssl.PEM_cert_to_DER_cert(open(sys.argv[2]).read())).decode()
assert server["tls_connection_policies"][0]["client_authentication"]["ca"]["trusted_ca_certs"] == [der]
PY
echo "-- $fingerprint"

echo "== forget won't take the last CA from a host that requires origin pull"
expect_refusal "requires origin pull, and without a CA" run "bedrock edge origin-pull forget $op $fingerprint"
expect_refusal "requires origin pull, and without a CA" run "bedrock edge origin-pull forget $op"
[[ "$(cas)" == "$fingerprint" ]] || fail "a refused forget changed $op's CAs"
expect "$op, the minted leaf" 200 "$(get "$op" "$(presenting op-leaf)")"

echo "== rotation: minting again trusts a second CA, and the first stays until it is forgotten"
mint op-next
[[ "$(cas | grep -c . || true)" == 2 ]] || fail "$op doesn't trust both CAs"
expect "$op, the first leaf" 200 "$(get "$op" "$(presenting op-leaf)")"
expect "$op, the new leaf" 200 "$(get "$op" "$(presenting op-next)")"
run "bedrock edge origin-pull forget $op $fingerprint"
expect "$op, the first leaf, its CA forgotten" 000 "$(get "$op" "$(presenting op-leaf)")"
expect "$op, the new leaf" 200 "$(get "$op" "$(presenting op-next)")"

echo "== without origin_pull again, the edge is as it was, and the CA can go"
manifest
deploy "without origin_pull"
server >"$work/off.json"
no_policy "$work/off.json"
same_routes "$work/off.json" "$op"
same_routes "$work/off.json" "$direct"
expect "$op, no certificate" 200 "$(get "$op")"
expect "port 80 for $op, as before" "${op80//./\\.}" "$(http80 "$op")"
run "bedrock edge origin-pull forget $op"
[[ -z "$(cas)" ]] || fail "$op still trusts a CA"
run 'bedrock edge origin-pull list'

echo "Origin pull proven: required is refused until a CA is trusted; the minted leaf is a year's client certificate in a new file; optional checks a presented certificate and the access log names it; required takes only the minted leaf, redirects port 80, answers a mismatched name with 421 and leaves a direct host as it was; forget keeps a required host's last CA; a second mint rotates without a gap; and taking origin_pull off restores the edge"
