#!/bin/sh
# End-to-end check: the server image plus real agents on several distros.
#
#   scripts/e2e.sh          build, run, check, clean up
#   KEEP=1 scripts/e2e.sh   leave everything running afterwards
#
# Starts Postgres and the server on a private Docker network (no published
# ports except Postgres on 127.0.0.1:55434 for inspection; E2E_PG_PORT
# moves it), creates an
# enrollment token directly in the database, then runs the real install.sh
# inside distro containers. Those have no systemd, so a stub systemctl runs
# the agent in a loop that does what the unit does: the startup guard, then
# the agent, restarted whenever it exits. Last, the server is restarted on a
# newer build and every agent updates itself to it.
#
# Agents only install releases signed by a key built into them, so the
# images are built from a copy of the source whose release-keys.pem also
# trusts a throwaway key, which signs them as the release workflow does.
#
# Containers: the first distro's agent reads this machine's Docker socket
# (it only ever sends GET requests), which runs a Compose-labelled container
# for it to find; the second serves TLS on a port and keeps a certificate file.
# E2E_DOCKER=0 leaves the socket out.
#
# Jobs: a real package upgrade on the first two
# distros, a service restart (through the systemctl stub) and a library
# script, which the second refuses by its local policy.
#
# Changes: a freeze holds a change until it's lifted, the second distro
# upgrades one package pinned to its exact version, and a patch group runs on its
# schedule as a Standard change from an approved change model.
#
# Alerts and CVEs: the server syncs OSV data from a fixture mirror built
# from what the first two distros have installed and pending, matches it, and fires the
# fixable-CVE and reboot-pending alerts.
#
# Virtualization: a virsh stub in the first distro reports a libvirt guest
# whose NIC has the second distro's MAC, which the server links to that host. (Cluster mode
# is checked by hand against k3s; see docs/agent.md §6.)
set -eu

NET=baseline-e2e
PG=baseline-e2e-pg
SRV=baseline-e2e
DISTROS=${DISTROS:-"ubuntu:24.04 rockylinux:9 fedora:42"}
cd "$(dirname "$0")/.."

DOCKER=${E2E_DOCKER:-1}

WORK=$(mktemp -d)

cleanup() {
	[ "${1:-}" != force ] && [ "${KEEP:-}" = 1 ] && return
	docker rm -f $SRV $PG $(docker ps -aq --filter label=baseline-e2e-agent) baseline-e2e-web baseline-e2e-osv >/dev/null 2>&1 || true
	docker network rm $NET >/dev/null 2>&1 || true
	docker volume rm baseline-e2e-data >/dev/null 2>&1 || true
}
trap 'cleanup; rm -rf "$WORK"' EXIT
cleanup force

echo "== build"
mkdir "$WORK/src"
git ls-files -co --exclude-standard -z | tar --null -T - -cf - | tar -xf - -C "$WORK/src"
openssl genpkey -algorithm ed25519 -out "$WORK/release.key" 2>/dev/null
openssl pkey -in "$WORK/release.key" -pubout >>"$WORK/src/internal/pki/release-keys.pem"
build() {
	docker build -q --secret id=release_signing_key,src="$WORK/release.key" \
		--build-arg VERSION="$1" -t baseline-server:"$1" "$WORK/src" >/dev/null
}
build e2e

echo "== start postgres and server"
docker network create $NET >/dev/null
docker run -d --name $PG --network $NET -p 127.0.0.1:${E2E_PG_PORT:-55434}:5432 \
	-e POSTGRES_USER=baseline -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=baseline postgres:18 >/dev/null
KEY=$(openssl rand -base64 32)
server() {
	docker run -d --name $SRV --network $NET -v baseline-e2e-data:/data \
		-e BASELINE_DB_URL="postgres://baseline:e2e@$PG:5432/baseline?sslmode=disable" \
		-e BASELINE_PUBLIC_URL="http://$SRV:8080" \
		-e BASELINE_GRPC_PUBLIC_ADDR="$SRV:8443" \
		-e BASELINE_OIDC_ISSUER=https://auth.invalid/ -e BASELINE_OIDC_CLIENT_ID=baseline \
		-e BASELINE_COOKIE_KEY="$KEY" -e BASELINE_SECRET_KEY="$KEY" -e BASELINE_OSV_URL=http://baseline-e2e-osv:8000 \
		-e BASELINE_LOG_LEVEL=Info "$1" >/dev/null
	i=0
	until docker exec $SRV /app/baseline-server healthcheck >/dev/null 2>&1; do
		i=$((i + 1)); [ $i -lt 60 ] || { docker logs $SRV; exit 1; }
		sleep 1
	done
}
server baseline-server:e2e

echo "== create an enrollment token"
SECRET_HEX=$(openssl rand -hex 24)
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
SECRET=$(printf %s "$SECRET_HEX" | xxd -r -p | b64url)
HASH=$(printf %s "$SECRET_HEX" | xxd -r -p | sha256sum | cut -d' ' -f1)
docker cp $SRV:/data/pki/ca.crt /tmp/baseline-e2e-ca.crt >/dev/null
FPR=$(openssl x509 -in /tmp/baseline-e2e-ca.crt -outform der | openssl dgst -sha256 -binary | b64url)
TOKEN="baseline1.$SECRET.$FPR"
docker exec $PG psql -qU baseline -d baseline -c \
	"INSERT INTO enrollment_token (name, secret_hash, expires_at) VALUES ('e2e', decode('$HASH','hex'), now() + interval '1 hour')"

# What the systemd unit does: ExecStartPre (the guard, from the previous
# binary), ExecStart, and Restart=always.
LOOP='#!/bin/sh
echo $$ >/run/baseline-loop.pid
while :; do
	[ -x /usr/local/libexec/baseline/baseline-agent.prev ] && /usr/local/libexec/baseline/baseline-agent.prev guard >>/var/log/baseline-agent.log 2>&1
	/usr/local/libexec/baseline/baseline-agent run >>/var/log/baseline-agent.log 2>&1 &
	echo $! >/run/baseline-agent.pid
	wait $!
	sleep 1
done'
STUB='#!/bin/sh
echo "systemctl $*" >>/tmp/systemctl.log
case "$*" in
"restart baseline-agent")
	for f in /run/baseline-loop.pid /run/baseline-agent.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; done
	sleep 1
	nohup /usr/local/sbin/baseline-agent-loop >/dev/null 2>&1 & ;;
esac'

# A container that looks like part of a Compose project whose file lives in
# the first agent's container, so the stack is "defined" there.
if [ "$DOCKER" = 1 ]; then
	docker run -d --name baseline-e2e-web --label com.docker.compose.project=e2e \
		--label com.docker.compose.service=web --label com.docker.compose.project.working_dir=/srv/e2e \
		--label com.docker.compose.project.config_files=/srv/e2e/compose.yaml \
		alpine:latest sleep infinity >/dev/null
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 20 -subj /CN=e2e.baseline.test \
	-addext subjectAltName=DNS:e2e.baseline.test -keyout /tmp/baseline-e2e.key -out /tmp/baseline-e2e.crt 2>/dev/null

n=0
for img in $DISTROS; do
	n=$((n + 1))
	name="baseline-e2e-$(echo "$img" | tr ':.' '--')"
	echo "== $img: install.sh"
	sock=""
	[ $n -eq 1 ] && [ "$DOCKER" = 1 ] && sock="-v /var/run/docker.sock:/var/run/docker.sock"
	docker run -d --name "$name" --hostname "$name" --label baseline-e2e-agent --network $NET $sock "$img" sleep infinity >/dev/null
	case $n in
	1)	# Compose file for the stack above; a pending reboot.
		docker exec "$name" sh -c 'mkdir -p /srv/e2e && printf "services:\n  web:\n    image: alpine:latest\n    environment:\n      DB_PASSWORD: hunter2\n" >/srv/e2e/compose.yaml
			printf "linux-image-e2e\n" >/var/run/reboot-required.pkgs && touch /var/run/reboot-required' ;;
	2)	# A certificate on disk, and the same one served on a port.
		docker cp /tmp/baseline-e2e.crt "$name":/etc/pki/tls/certs/e2e.crt >/dev/null
		docker cp /tmp/baseline-e2e.key "$name":/root/e2e.key >/dev/null
		docker exec -d "$name" python3 -c '
import http.server, ssl
s = http.server.HTTPServer(("0.0.0.0", 9443), http.server.SimpleHTTPRequestHandler)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/etc/pki/tls/certs/e2e.crt", "/root/e2e.key")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()' ;;
	esac
	docker exec "$name" sh -c '
		set -e
		# The Ubuntu image deletes downloaded .debs after every apt-get
		# update, which breaks an install racing the agent'"'"'s own update.
		# Hosts have no such hook.
		rm -f /etc/apt/apt.conf.d/docker-clean
		command -v curl >/dev/null || (apt-get -qq update && apt-get -qq install -y curl >/dev/null)
		# Containers lack a machine-id; give each its own.
		[ -s /etc/machine-id ] || cat /proc/sys/kernel/random/uuid | tr -d - >/etc/machine-id
		printf "%s\n" "$1" >/usr/local/sbin/systemctl && chmod +x /usr/local/sbin/systemctl
		printf "%s\n" "$3" >/usr/local/sbin/baseline-agent-loop && chmod +x /usr/local/sbin/baseline-agent-loop
		curl -fsSL http://'$SRV':8080/install.sh | sh -s -- --token "$2"
	' sh "$STUB" "$TOKEN" "$LOOP"
done

# Every section, including the update check (a cold dnf cache takes a while).
echo "== wait for inventory"
want=$(echo $DISTROS | wc -w)
q() { docker exec $PG psql -qtAU baseline -d baseline -c "$1"; }
i=0
until [ "$(q "SELECT count(*) FROM host_inventory")" -ge $((want * 10)) ]; do
	i=$((i + 1)); [ $i -lt 300 ] || { q "SELECT h.hostname, i.section FROM host_inventory i JOIN host h ON h.ci_id = i.host ORDER BY 1, 2"; docker logs $SRV; exit 1; }
	sleep 1
done

echo "== results"
q "SELECT h.hostname, h.os_pretty, h.kernel, h.connected, h.duplicate_identity, h.agent_arch,
          (SELECT count(*) FROM host_package p WHERE p.host = h.ci_id) AS packages,
          (SELECT string_agg(DISTINCT manager, ',') FROM host_package p WHERE p.host = h.ci_id) AS managers,
          (SELECT count(*) FROM host_update u WHERE u.host = h.ci_id) AS updates,
          (SELECT count(*) FROM host_update u WHERE u.host = h.ci_id AND u.security) AS security,
          (SELECT count(*) FROM metric_series m WHERE m.host = h.ci_id) AS series
   FROM host h ORDER BY 1" | column -t -s '|'
q "SELECT h.hostname, i.data->'warnings' FROM host_inventory i JOIN host h ON h.ci_id = i.host
   WHERE i.section = 'updates' AND i.data ? 'warnings'" | column -t -s '|'
q "SELECT action, count(*) FROM audit_log GROUP BY 1 ORDER BY 1" | column -t -s '|'

fail=0
[ "$(q "SELECT count(*) FROM host WHERE connected")" -eq "$want" ] || { echo "FAIL: not every agent is connected"; fail=1; }
[ "$(q "SELECT count(*) FROM host WHERE os_pretty = '' OR kernel = ''")" -eq 0 ] || { echo "FAIL: missing OS data"; fail=1; }
[ "$(q "SELECT count(*) FROM host h WHERE NOT EXISTS (SELECT 1 FROM host_package p WHERE p.host = h.ci_id)")" -eq 0 ] || { echo "FAIL: a host has no packages"; fail=1; }
[ "$(q "SELECT count(*) FROM host WHERE agent_arch = ''")" -eq 0 ] || { echo "FAIL: an agent didn't report its architecture"; fail=1; }
[ "$(q "SELECT count(DISTINCT host) FROM host_inventory WHERE section = 'smart'")" -eq "$want" ] || { echo "FAIL: missing smart sections"; fail=1; }
[ "$(q "SELECT count(*) FROM ci_history WHERE section = 'updates'")" -eq 0 ] || { echo "FAIL: updates recorded in history"; fail=1; }

echo "== containers, services, ports, certificates, reboot"
q "SELECT h.hostname, h.reboot_required, (SELECT count(*) FROM container c WHERE c.host = h.ci_id) AS containers,
          (SELECT count(*) FROM host_port p WHERE p.host = h.ci_id) AS ports,
          (SELECT count(*) FROM ci_cert x WHERE x.ci_id = h.ci_id) AS certs
   FROM host h ORDER BY 1" | column -t -s '|'
first=$(echo $DISTROS | cut -d' ' -f1)
second=$(echo $DISTROS | cut -d' ' -f2)
h1="baseline-e2e-$(echo "$first" | tr ':.' '--')"
h2="baseline-e2e-$(echo "$second" | tr ':.' '--')"
third=$(echo $DISTROS | cut -d' ' -f3)
h3="baseline-e2e-$(echo "$third" | tr ':.' '--')"
[ "$(q "SELECT reboot_required FROM host WHERE hostname = '$h1'")" = t ] || { echo "FAIL: $h1 should need a reboot"; fail=1; }
[ "$(q "SELECT count(*) FROM host_port p JOIN host h ON h.ci_id = p.host WHERE h.hostname = '$h2' AND p.port = 9443 AND p.process LIKE 'python%'")" -eq 1 ] ||
	{ echo "FAIL: $h2's listener on 9443 not found"; fail=1; }
[ "$(q "SELECT count(*) FROM ci_cert x JOIN host h ON h.ci_id = x.ci_id WHERE h.hostname = '$h2' AND x.subject = 'CN=e2e.baseline.test'
        AND x.location IN ('/etc/pki/tls/certs/e2e.crt', 'tcp:9443')")" -eq 2 ] || { echo "FAIL: $h2's certificate not found in the file and on the port"; fail=1; }
[ "$(q "SELECT count(*) FROM host_inventory WHERE section = 'services'")" -eq "$want" ] || { echo "FAIL: missing services sections"; fail=1; }
if [ "$DOCKER" = 1 ]; then
	[ "$(q "SELECT count(*) FROM container c JOIN host h ON h.ci_id = c.host WHERE h.hostname = '$h1' AND c.name = 'baseline-e2e-web'
	        AND c.compose_project = 'e2e' AND c.state = 'running'")" -eq 1 ] || { echo "FAIL: the e2e container wasn't found"; fail=1; }
	[ "$(q "SELECT count(*) FROM compose_stack WHERE project = 'e2e' AND NOT orphaned AND present")" -eq 1 ] || { echo "FAIL: the e2e stack isn't defined"; fail=1; }
	q "SELECT data::text FROM host_inventory WHERE section = 'containers'" | grep -q hunter2 && { echo "FAIL: a Compose secret left the host"; fail=1; }
	[ "$(q "SELECT count(*) FROM ci_relationship r JOIN container c ON c.ci_id = r.from_ci WHERE c.name = 'baseline-e2e-web'")" -eq 2 ] ||
		{ echo "FAIL: the e2e container's relationships are missing"; fail=1; }
	# The server checks Docker Hub itself; offline machines only warn.
	i=0
	until [ -n "$(q "SELECT 1 FROM image_check WHERE image_ref = 'docker.io/library/alpine:latest'")" ]; do
		i=$((i + 1)); [ $i -lt 30 ] || break
		sleep 1
	done
	q "SELECT image_ref, left(latest_digest, 19), error FROM image_check WHERE image_ref = 'docker.io/library/alpine:latest'" | column -t -s '|'
	[ -n "$(q "SELECT 1 FROM image_check WHERE image_ref = 'docker.io/library/alpine:latest' AND latest_digest <> ''")" ] ||
		echo "WARN: no registry digest for alpine:latest (no internet access?)"
fi

echo "== metrics arrive"
i=0
until [ "$(q "SELECT count(DISTINCT s.host) FROM metric_raw r JOIN metric_series s ON s.id = r.series_id WHERE s.kind = 'mem'")" -eq "$want" ]; do
	i=$((i + 1)); [ $i -lt 90 ] || { echo "FAIL: not every host sent metrics"; fail=1; break; }
	sleep 1
done

echo "== OSV fixture: a fixable and an unfixed vulnerability per distro"
# Records built from what the hosts have: a package with a pending update,
# fixed exactly in that update, and one without an update, fixed nowhere.
osv() { # host ecosystem id-prefix summary
	q "SELECT jsonb_build_object('id', '$3-' || n, 'modified', now(), 'summary', '$4',
	          'upstream', jsonb_build_array('CVE-2099-' || (1000 + n)),
	          'affected', jsonb_build_array(jsonb_build_object(
	              'package', jsonb_build_object('name', src, 'ecosystem', '$2'),
	              'ranges', jsonb_build_array(jsonb_build_object('type', 'ECOSYSTEM', 'events',
	                  CASE WHEN fixed = '' THEN jsonb_build_array(jsonb_build_object('introduced', '0'))
	                  ELSE jsonb_build_array(jsonb_build_object('introduced', '0'), jsonb_build_object('fixed', fixed)) END)),
	              'ecosystem_specific', jsonb_build_object('ubuntu_priority', 'high'))))
	   FROM (SELECT 1 AS n, COALESCE(NULLIF(p.source, ''), p.name) AS src, u.candidate_ver AS fixed
	         FROM host_update u JOIN host h ON h.ci_id = u.host
	         JOIN host_package p ON p.host = u.host AND p.name = u.name AND p.arch = u.arch
	         WHERE h.hostname = '$1' AND u.installed_ver <> '' AND NOT u.image ORDER BY u.name LIMIT 1) x
	   UNION ALL
	   SELECT jsonb_build_object('id', '$3-2', 'modified', now(), 'summary', '$4 (unfixed)',
	          'affected', jsonb_build_array(jsonb_build_object(
	              'package', jsonb_build_object('name', COALESCE(NULLIF(p.source, ''), p.name), 'ecosystem', '$2'),
	              'ranges', jsonb_build_array(jsonb_build_object('type', 'ECOSYSTEM', 'events',
	                  jsonb_build_array(jsonb_build_object('introduced', '0')))))))
	   FROM (SELECT p.* FROM host_package p JOIN host h ON h.ci_id = p.host
	         WHERE h.hostname = '$1' AND p.manager IN ('apt', 'dnf') AND NOT EXISTS
	               (SELECT 1 FROM host_update u WHERE u.host = p.host AND u.name = p.name)
	         ORDER BY p.name LIMIT 1) p"
}
osvdir=$(mktemp -d)
mkdir -p "$osvdir/Ubuntu" "$osvdir/Rocky Linux"
osv "$h1" "Ubuntu:24.04:LTS" UBUNTU-CVE-2099 "e2e ubuntu" >"$osvdir/Ubuntu/records.jsonl"
osv "$h2" "Rocky Linux:9" RLSA-2099:0 "Important: e2e rocky" >"$osvdir/Rocky Linux/records.jsonl"
fixable=$(cat "$osvdir/Ubuntu/records.jsonl" "$osvdir/Rocky Linux/records.jsonl" | grep -c '"fixed"' || true)
# A mirror in the shape of OSV's bucket: all.zip and modified_id.csv per
# distro, served by Python from the Rocky image.
docker run -d --name baseline-e2e-osv --network $NET -v "$osvdir:/srv/osv" rockylinux:9 sh -c '
	cd /srv/osv && python3 -c "
import json, os, zipfile
for d in os.listdir(\".\"):
    recs = [json.loads(l) for l in open(d + \"/records.jsonl\") if l.strip()]
    with zipfile.ZipFile(d + \"/all.zip\", \"w\") as z:
        for r in recs:
            z.writestr(r[\"id\"] + \".json\", json.dumps(r))
    open(d + \"/modified_id.csv\", \"w\").write(\"\".join(r[\"modified\"][:19] + \"Z,\" + r[\"id\"] + \"\\n\" for r in recs))
" && exec python3 -m http.server 8000' >/dev/null
# The hosts reported before the mirror existed, so the first sync failed and
# waits an hour; make it due again. The package change below wakes it.
q "UPDATE vuln_source SET tried_at = now() - interval '2 hours'" >/dev/null

echo "== reinstall over an existing agent keeps its identity"
first=$(echo $DISTROS | cut -d' ' -f1)
name="baseline-e2e-$(echo "$first" | tr ':.' '--')"
before=$(docker exec "$name" cat /var/lib/baseline/agent-id)
docker exec "$name" sh -c "curl -fsSL http://$SRV:8080/install.sh | sh" >/dev/null
[ "$(docker exec "$name" cat /var/lib/baseline/agent-id)" = "$before" ] || { echo "FAIL: reinstall changed the agent ID"; fail=1; }

echo "== a package change shows up in history after the agent restarts"
# The agent may be refreshing apt's lists right after the reinstall: wait for
# the lock rather than fail.
docker exec "$name" sh -c 'apt-get -qq -o DPkg::Lock::Timeout=120 install -y tree >/tmp/apt.log 2>&1 || { cat /tmp/apt.log; exit 1; }
	systemctl restart baseline-agent'
i=0
until [ "$(q "SELECT count(*) FROM ci_history WHERE section = 'packages' AND diff::text LIKE '%apt/tree%'")" -ge 1 ]; do
	i=$((i + 1)); [ $i -lt 30 ] || { echo "FAIL: no history entry for the new package"; fail=1; break; }
	sleep 1
done
[ "$(q "SELECT count(*) FROM audit_log WHERE action = 'host.identity_conflict'")" -eq 0 ] || { echo "FAIL: restart looked like a clone"; fail=1; }

echo "== vulnerabilities and alerts"
i=0
until [ "$(q "SELECT count(DISTINCT host) FROM host_vuln")" -ge 2 ]; do
	i=$((i + 1)); [ $i -lt 120 ] || { echo "FAIL: no matches"; q "SELECT * FROM vuln_source"; fail=1; break; }
	sleep 1
done
q "SELECT s.ecosystem, s.dump, s.vulns, s.error FROM vuln_source s ORDER BY 1" | column -t -s '|'
q "SELECT h.hostname, h.vuln_ecosystem, v.vuln_id, v.package, v.installed_ver, v.fixed_ver, v.fix_available, v.severity
   FROM host_vuln v JOIN host h ON h.ci_id = v.host ORDER BY 1, 3" | column -t -s '|'
[ "$(q "SELECT count(DISTINCT vuln_id) FROM host_vuln WHERE fix_available")" -eq "$fixable" ] || { echo "FAIL: expected $fixable fixable vulnerabilities"; fail=1; }
[ "$(q "SELECT count(*) FROM host_vuln WHERE fixed_ver = '' AND vuln_id LIKE '%-2'")" -ge 2 ] || { echo "FAIL: unfixed records not matched"; fail=1; }
[ "$(q "SELECT count(*) FROM host WHERE hostname = '$h3' AND vulns_at IS NOT NULL AND vuln_ecosystem = ''")" -eq 1 ] ||
	{ echo "FAIL: $h3 (no OSV ecosystem) wasn't marked uncovered"; fail=1; }
# Rules run every minute: make the first host's reboot a week old.
q "UPDATE host SET reboot_required_since = now() - interval '8 days' WHERE hostname = '$h1'" >/dev/null
want_alerts=1
[ "$fixable" -gt 0 ] && want_alerts=2
i=0
until [ "$(q "SELECT count(*) FROM alert a JOIN alert_rule r ON r.id = a.rule_id
              WHERE a.state = 'firing' AND r.kind IN ('reboot_pending', 'cve_fixable')")" -ge $want_alerts ]; do
	i=$((i + 1)); [ $i -lt 90 ] || { echo "FAIL: alerts didn't fire"; fail=1; break; }
	sleep 1
done
q "SELECT r.name, a.state, a.severity, a.summary FROM alert a JOIN alert_rule r ON r.id = a.rule_id ORDER BY 1" | column -t -s '|'
[ "$fixable" -gt 0 ] || echo "WARN: no pending updates to build a fixable record from"

echo "== jobs: upgrades, a service restart and a library script, under each host's local policy"
# The second host refuses scripts in its agent.conf (the agent restarts to
# read it, and reports it in Hello).
docker exec "$h2" sh -c 'echo "allow_scripts = false" >>/etc/baseline/agent.conf && systemctl restart baseline-agent'
i=0
until [ "$(q "SELECT local_policy->>'allow_scripts' FROM host WHERE hostname = '$h2' AND connected")" = false ]; do
	i=$((i + 1)); [ $i -lt 60 ] || { echo "FAIL: $h2 didn't report its policy"; fail=1; break; }
	sleep 1
done
# What "Submit and approve" records: approved changes that the dispatcher
# starts within seconds. Scripts are library versions, checked by SHA-256.
q "INSERT INTO app_user (oidc_sub, email, name) VALUES ('e2e', 'e2e@baseline.test', 'e2e')" >/dev/null
BODY='#!/bin/sh
echo "hello $1 $BASELINE_PARAM_N from $(id -u) in $(pwd)"'
q "INSERT INTO script (name) VALUES ('e2e-hello')" >/dev/null
q "INSERT INTO script_version (script_id, version, interpreter, params, risk, body, sha256)
   SELECT id, 1, '/bin/sh', '[{\"name\":\"who\",\"type\":\"string\"},{\"name\":\"n\",\"type\":\"int\"}]', 'low', \$\$$BODY\$\$,
          encode(sha256(convert_to(\$\$$BODY\$\$, 'UTF8')), 'hex') FROM script WHERE name = 'e2e-hello'" >/dev/null
job() { # host action params [script]
	q "WITH c AS (INSERT INTO change (title, risk, state, requested_by, approved_at)
	              VALUES ('e2e $2', 'low', 'approved', (SELECT id FROM app_user WHERE oidc_sub = 'e2e'), now()) RETURNING id)
	   INSERT INTO job (change_id, seq, host, action, params, timeout_s, script_id, script_version)
	   SELECT c.id, 1, h.ci_id, '$2', '$3', 3600, (SELECT id FROM script WHERE name = '${4:-}'), CASE WHEN '${4:-}' <> '' THEN 1 END
	   FROM c, host h WHERE h.hostname = '$1'" >/dev/null
}
job "$h1" pkg.upgrade '{"mode":"all","reboot":"never"}'
job "$h1" service.restart '{"unit":"e2e.service"}'
job "$h2" pkg.upgrade '{"mode":"security","reboot":"never"}'
job "$h2" script.run '{"script_id":"x","name":"e2e-hello","version":1,"args":{"who":"e2e","n":"42"}}' e2e-hello
job "$h3" script.run '{"script_id":"x","name":"e2e-hello","version":1,"args":{"who":"e2e","n":"42"}}' e2e-hello
i=0
until [ "$(q "SELECT count(*) FROM job WHERE state IN ('queued', 'dispatched', 'running')")" -eq 0 ]; do
	i=$((i + 1)); [ $i -lt 600 ] || { echo "FAIL: jobs didn't finish"; fail=1; break; }
	sleep 1
done
q "SELECT h.hostname, j.action, j.state, j.exit_code, j.error, jsonb_array_length(COALESCE(j.result->'changed', '[]')) AS upgraded,
          c.state AS change, j.output_bytes
   FROM job j JOIN host h ON h.ci_id = j.host JOIN change c ON c.id = j.change_id ORDER BY 1, 2" | column -t -s '|'
jstate() { q "SELECT j.state FROM job j JOIN host h ON h.ci_id = j.host WHERE h.hostname = '$1' AND j.action = '$2'"; }
[ "$(jstate "$h1" pkg.upgrade)" = succeeded ] || { echo "FAIL: $h1's upgrade"; fail=1; }
[ "$(jstate "$h2" pkg.upgrade)" = succeeded ] || { echo "FAIL: $h2's security upgrade"; fail=1; }
[ "$(jstate "$h1" service.restart)" = succeeded ] || { echo "FAIL: $h1's service restart"; fail=1; }
docker exec "$h1" grep -q "systemctl restart e2e.service" /tmp/systemctl.log || { echo "FAIL: systemctl wasn't run"; fail=1; }
[ "$(jstate "$h2" script.run)" = rejected ] || { echo "FAIL: $h2 ran a script despite allow_scripts = false"; fail=1; }
[ "$(jstate "$h3" script.run)" = succeeded ] || { echo "FAIL: $h3's script"; fail=1; }
q "SELECT o.chunk FROM job_output o JOIN job j ON j.id = o.job_id JOIN host h ON h.ci_id = j.host
   WHERE h.hostname = '$h3' AND j.action = 'script.run' ORDER BY o.id" | grep -q "hello e2e 42 from 0 in /" ||
	{ echo "FAIL: the script's output"; fail=1; }
[ "$(q "SELECT count(*) FROM change WHERE title LIKE 'e2e %' AND state NOT IN ('implemented', 'failed')")" -eq 0 ] ||
	{ echo "FAIL: changes didn't end"; fail=1; }
# What the upgrade changed is in history, attributed to its change.
if [ "$(q "SELECT jsonb_array_length(COALESCE(j.result->'changed', '[]')) FROM job j JOIN host h ON h.ci_id = j.host
          WHERE h.hostname = '$h1' AND j.action = 'pkg.upgrade'")" -gt 0 ]; then
	i=0
	until [ "$(q "SELECT count(*) FROM ci_history x JOIN job j ON j.change_id = x.change_id JOIN host h ON h.ci_id = x.ci_id
	              WHERE h.hostname = '$h1' AND x.section = 'packages' AND j.action = 'pkg.upgrade'")" -ge 1 ]; do
		i=$((i + 1)); [ $i -lt 60 ] || { echo "FAIL: the upgrade's package changes aren't attributed to its change"; fail=1; break; }
		sleep 1
	done
else
	echo "WARN: $first had nothing to upgrade"
fi
[ "$(q "SELECT count(*) FROM audit_log WHERE action IN ('job.dispatch', 'job.result')")" -ge 10 ] || { echo "FAIL: jobs not audited"; fail=1; }

echo "== change management: freezes, pinned versions, patch groups"
# A freeze over every host holds an approved change; lifting it lets it run.
q "INSERT INTO maintenance_window (name, kind, cron, duration_s) VALUES ('e2e freeze', 'freeze', '$(date -u +%-M) $(date -u +%-H) * * *', 600)" >/dev/null
q "INSERT INTO change (title, risk, state, requested_by, approved_at)
   VALUES ('e2e frozen', 'low', 'submitted', (SELECT id FROM app_user WHERE oidc_sub = 'e2e'), now())" >/dev/null
q "INSERT INTO job (change_id, seq, host, action, params, timeout_s)
   SELECT c.id, 1, h.ci_id, 'service.restart', '{\"unit\":\"e2e.service\"}', 300 FROM change c, host h
   WHERE c.title = 'e2e frozen' AND h.hostname = '$h1'" >/dev/null
q "INSERT INTO change_ci (change_id, ci_id) SELECT change_id, host FROM job j JOIN change c ON c.id = j.change_id
   WHERE c.title = 'e2e frozen'" >/dev/null
q "UPDATE change SET state = 'approved' WHERE title = 'e2e frozen'" >/dev/null
i=0
until [ "$(q "SELECT state FROM change WHERE title = 'e2e frozen'")" = scheduled ]; do
	i=$((i + 1)); [ $i -lt 30 ] || { echo "FAIL: the freeze didn't hold the change"; fail=1; break; }
	sleep 1
done
q "SELECT state, schedule_note FROM change WHERE title = 'e2e frozen'" | grep -q "held by freeze e2e freeze" ||
	{ echo "FAIL: no freeze note"; fail=1; }
q "DELETE FROM maintenance_window WHERE name = 'e2e freeze'" >/dev/null
# The change was planned for the freeze's end; bring that forward.
q "UPDATE change SET planned_start = now() WHERE title = 'e2e frozen'" >/dev/null
i=0
until [ "$(q "SELECT state FROM change WHERE title = 'e2e frozen'")" = implemented ]; do
	i=$((i + 1)); [ $i -lt 60 ] || { echo "FAIL: the change didn't run after the freeze"; fail=1; break; }
	sleep 1
done

# The second host upgrades one package to exactly its candidate version, as
# patch-group promotion does.
pin=$(q "SELECT name || '|' || candidate_ver FROM host_update u JOIN host h ON h.ci_id = u.host
         WHERE h.hostname = '$h2' AND u.manager = 'dnf' AND u.installed_ver <> '' AND NOT u.image ORDER BY name LIMIT 1")
if [ -n "$pin" ]; then
	pkg=${pin%%|*}; ver=${pin#*|}
	job "$h2" pkg.upgrade "{\"mode\":\"selected\",\"packages\":[\"$pkg\"],\"versions\":{\"$pkg\":\"$ver\"},\"reboot\":\"never\"}"
	i=0
	until [ "$(q "SELECT count(*) FROM job WHERE state IN ('queued', 'dispatched', 'running')")" -eq 0 ]; do
		i=$((i + 1)); [ $i -lt 600 ] || { echo "FAIL: the pinned upgrade didn't finish"; fail=1; break; }
		sleep 1
	done
	q "SELECT o.chunk FROM job_output o JOIN job j ON j.id = o.job_id WHERE j.params ? 'versions' ORDER BY o.id" | grep -q -- "$pkg-$ver" ||
		{ echo "FAIL: dnf wasn't asked for $pkg-$ver"; fail=1; }
	[ "$(q "SELECT count(*) FROM job WHERE params ? 'versions' AND state = 'succeeded'
	        AND result->'changed' @> '[{\"name\":\"$pkg\"}]' AND result::text LIKE '%$ver%'")" -eq 1 ] ||
		{ echo "FAIL: $pkg wasn't upgraded to exactly $ver"; q "SELECT state, error FROM job WHERE params ? 'versions'"; fail=1; }
else
	echo "WARN: $second had no dnf update left to pin"
fi
[ "$(q "SELECT count(*) FROM host WHERE 'pkg-pin' = ANY(capabilities)")" -eq "$want" ] || { echo "FAIL: agents don't report pkg-pin"; fail=1; }

# A patch group on the third host, every minute, under an approved model
# that runs the library script: one cycle, one closed Standard change.
q "INSERT INTO host_group (name) VALUES ('e2e-patch')" >/dev/null
q "INSERT INTO host_group_member (group_id, ci_id) SELECT g.id, h.ci_id FROM host_group g, host h
   WHERE g.name = 'e2e-patch' AND h.hostname = '$h3'" >/dev/null
q "INSERT INTO change_model (name, action, params, script_id, script_version, risk, state, approved_at)
   SELECT 'e2e hello', 'script.run', jsonb_build_object('script_id', id::text, 'name', 'e2e-hello', 'version', 1,
          'args', '{\"who\":\"patch\",\"n\":\"1\"}'::jsonb), id, 1, 'low', 'approved', now()
   FROM script WHERE name = 'e2e-hello'" >/dev/null
q "INSERT INTO patch_group (name, host_group_id, schedule_cron, change_model_id, last_run_at)
   SELECT 'e2e', g.id, '* * * * *', m.id, now() - interval '1 minute' FROM host_group g, change_model m
   WHERE g.name = 'e2e-patch' AND m.name = 'e2e hello'" >/dev/null
i=0
until [ "$(q "SELECT result FROM patch_cycle ORDER BY started_at LIMIT 1")" = success ]; do
	i=$((i + 1)); [ $i -lt 180 ] || { echo "FAIL: the patch group's cycle didn't succeed"; q "SELECT result, reason FROM patch_cycle"; fail=1; break; }
	sleep 1
done
q "SELECT p.result, p.hosts, p.succeeded, c.kind, c.state FROM patch_cycle p JOIN change c ON c.id = p.change_id
   ORDER BY p.started_at LIMIT 1" | grep -q "success|1|1|standard|closed" || { echo "FAIL: the cycle's change"; fail=1; }
q "UPDATE patch_group SET enabled = false" >/dev/null
[ "$(q "SELECT count(*) FROM audit_log WHERE action LIKE 'patch_cycle.%'")" -ge 2 ] || { echo "FAIL: cycles not audited"; fail=1; }

echo "== virtualization: a libvirt host (a virsh stub) whose guest is the second distro"
# The guest's NIC has the second container's MAC, so the server joins the
# guest to the host its agent reports.
mac2=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' "$h2")
VMUUID=$(cat /proc/sys/kernel/random/uuid)
VIRSH='#!/bin/sh
case "$*" in
"--version") echo 10.0.0 ;;
"list --all --uuid"|"list --all --uuid --autostart") printf "%s\n\n" '"$VMUUID"' ;;
"domstate '"$VMUUID"'") echo running ;;
"dumpxml --inactive '"$VMUUID"'") cat <<XML
<domain type="kvm"><name>e2e-guest</name><uuid>'"$VMUUID"'</uuid><memory unit="MiB">2048</memory><vcpu>2</vcpu>
<os><type arch="x86_64" machine="pc-q35-9.2">hvm</type></os>
<devices><disk type="file" device="disk"><source file="/var/lib/libvirt/images/e2e.qcow2"/><target dev="vda" bus="virtio"/></disk>
<interface type="bridge"><mac address="'"$mac2"'"/><source bridge="br0"/><model type="virtio"/></interface></devices></domain>
XML
;;
*) echo "error: virsh stub: $*" >&2; exit 1 ;;
esac'
docker exec "$h1" sh -c 'printf "%s\n" "$1" >/usr/local/bin/virsh && chmod +x /usr/local/bin/virsh' sh "$VIRSH"
# On connect the agent sends every section the server lacks; restarting it
# reads the guests now rather than at the next 5-minute collection.
docker exec "$h1" systemctl restart baseline-agent
i=0
until [ "$(q "SELECT count(*) FROM vm_guest g JOIN ci_relationship r ON r.to_ci = g.ci_id AND r.kind = 'runs_on'
              JOIN host a ON a.ci_id = r.from_ci WHERE g.name = 'e2e-guest' AND a.hostname = '$h2'")" -eq 1 ]; do
	i=$((i + 1)); [ $i -lt 60 ] || { echo "FAIL: the libvirt guest wasn't found or linked to $h2"; q "SELECT name, macs, present FROM vm_guest"; fail=1; break; }
	sleep 1
done
q "SELECT g.name, g.platform, g.kind, g.state, h.hostname AS hypervisor FROM vm_guest g JOIN host h ON h.ci_id = g.host" | column -t -s '|'
[ "$(q "SELECT count(*) FROM ci c JOIN vm_guest g ON g.ci_id = c.id WHERE c.source = 'libvirt' AND c.source_key = '$VMUUID'")" -eq 1 ] ||
	{ echo "FAIL: the guest's CI"; fail=1; }
[ "$(q "SELECT count(DISTINCT host) FROM host_inventory WHERE section = 'vms'")" -eq 1 ] || { echo "FAIL: hosts without a hypervisor sent a vms section"; fail=1; }

echo "== self-update: a newer server publishes its agent, and every agent moves to it"
build e2e2
docker rm -f $SRV >/dev/null
# What Settings → Agents → Update agents records. Set while the server is
# down, every agent is offered the update when it reconnects.
q "UPDATE host SET agent_update_target = 'e2e2', agent_update_at = now() WHERE NOT revoked" >/dev/null
server baseline-server:e2e2
[ "$(q "SELECT count(*) FROM agent_release WHERE version IN ('e2e', 'e2e2')")" -eq 4 ] || { echo "FAIL: releases not published"; fail=1; }
i=0
until [ "$(q "SELECT count(*) FROM host WHERE agent_version = 'e2e2' AND connected AND agent_update_target = ''")" -eq "$want" ]; do
	i=$((i + 1)); [ $i -lt 120 ] || { echo "FAIL: agents didn't update"; q "SELECT hostname, agent_version, agent_update_target, agent_update_error FROM host"; fail=1; break; }
	sleep 1
done
for img in $DISTROS; do
	name="baseline-e2e-$(echo "$img" | tr ':.' '--')"
	docker exec "$name" sh -c '
		[ "$(/usr/local/libexec/baseline/baseline-agent version)" = e2e2 ] &&
		[ "$(/usr/local/libexec/baseline/baseline-agent.prev version)" = e2e ] &&
		[ ! -e /var/lib/baseline/update-pending.json ]' || { echo "FAIL: $img: binaries or probation marker wrong"; fail=1; }
done

docker logs $SRV 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "Gateway|Error|Fatal|Published" | tail -20
[ $fail -eq 0 ] && echo "== PASS"
exit $fail
