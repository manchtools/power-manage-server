# Power Manage server quickstart

<!-- docref: begin src=deploy/compose.yml#@deployment-services:3fac95e9 -->
The stack has exactly two services: Traefik and one control process with an
embedded SQLite database. Compose gives control no arguments and passes it the
rendered `config/control.env` as the container's environment file, and passes
Traefik `config/traefik-acme.env` and `config/traefik-dns.env` the same way.
The authoritative system design is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.
<!-- docref: end -->

## Prepare

Copy `.env.example` to `.env`, set the three required public values
(`CONTROL_DOMAIN`, `AGENT_DOMAIN`, and `ACME_EMAIL`), then give the audit
archive its own storage and run `./setup.sh`. `.env` carries only those values,
the optional ACME challenge selection below, and `IMAGE_TAG`; it is Compose's
own environment file, not control's configuration.

### Storage for the audit archive

<!-- docref: begin src=deploy/setup.sh#@archive-isolation:b4ebb270,cmd/control/config.go#validateArchiveIsolation:b9894a73,cmd/control/devauth_stub.go#archiveIsolationRelaxed:8de98d35 -->
`data/backups` must be on a different filesystem from the SQLite database under
`data/control`. Mount a second disk, an NFS or NAS export, or any
remote-backed volume there:

```bash
mkdir -p data && ln -s /srv/power-manage-archive data/backups
```

A symlink works as well as a mount point: Compose bind-mounts whatever the path
resolves to, so control sees that storage rather than the deploy tree's
filesystem. If a previous run already created the empty directory, `rmdir
data/backups` before linking.

This is a requirement, not a recommendation. The archive holds the anchors and
archived chain prefixes that prove the audit log was not rewritten, so control
compares the two filesystems at startup and refuses to run when they match —
there is no configuration variable that turns the check off. `setup.sh` applies
the same comparison first, naming both paths, so a deployment that cannot boot
is never rendered in the first place.
<!-- docref: end -->

For a single-node test box with no second disk, `ARCHIVE_LOOPBACK=1` (or
answering `loopback` in the guided run) makes `install.sh` create a 2 GiB
image at `data/backups.img`, mount it at `data/backups`, and persist the
mount in `/etc/fstab`. The check is satisfied — the archive really is a
separate filesystem — but it lives on the same disk, so it protects against
nothing that takes the disk with it: one disk failure or ransomware pass
still takes the audit log and its proof together. Test nodes only.

`install.sh` runs `setup.sh` for you and therefore stops at the same point.
Provide the archive storage under the install directory it created, then run
`./setup.sh && ./deploy.sh` there. It has no default release: `RELEASE_TAG`
must name a release tag such as `v2026.08.09-rc2`, because a branch name
installs whatever that branch pointed at on the day it ran.

Run from a terminal, `install.sh` asks for every value it was not given — the
two domains, the ACME email, the release, the certificate challenge, and the
archive storage choice — re-asking on invalid input with the same rules
`setup.sh` enforces. Without a terminal nothing prompts: a missing value keeps
refusing with the messages above, so scripted runs never hang. No prompt ever
asks for a secret; a `dns01` install stops after unpacking with
`config/traefik-dns.env` created empty at mode 0600, ready for the credential
to be pasted into, and names the two commands that finish the install.

### Certificates without a reachable port 80

Let's Encrypt proves you own `CONTROL_DOMAIN` and `AGENT_DOMAIN` before it
issues anything. By default it does so over HTTP, which requires this host to
be reachable from the internet on port 80. Behind CGNAT, on a residential line
where port 80 is blocked, or on a private network, it is not — set the ACME
challenge to DNS instead and Traefik proves ownership by writing a record into
your DNS zone:

```
ACME_CHALLENGE=dns01
ACME_DNS_PROVIDER=hetzner
```

`ACME_DNS_PROVIDER` is a [lego provider
code](https://go-acme.github.io/lego/dns/). The zone has to be served by that
provider, not merely registered there: Hetzner DNS answers for the domain only
once its nameservers are the ones delegated to it. Write that provider's
credentials into `config/traefik-dns.env`, one `KEY=VALUE` per line — for
Hetzner DNS, `HETZNER_API_TOKEN` with a Cloud Console API token (the
`HETZNER_API_KEY` variable selects the legacy DNS API that Hetzner shut down
in May 2026, which fails with an HTML-instead-of-JSON unmarshal error):

```bash
mkdir -p config && install -m 600 /dev/null config/traefik-dns.env
printf 'HETZNER_API_TOKEN=%s\n' "$token" >> config/traefik-dns.env
```

Traefik reads that file itself. `setup.sh` never copies or prints its contents,
and refuses a `dns01` run when the file is missing, empty, or readable by other
accounts — before it generates any key material, so a corrected run starts from
nothing. It renders the challenge selection into `config/traefik-acme.env`,
pins the propagation check to public resolvers — a split-horizon resolver at
home answers from the internal view of the zone, where the challenge record
does not exist, and the order would never complete — and waits 60 seconds
before that check, because the certificate authority validates from several
vantage points and a record one resolver already sees can still be missing at
the DNS operator's other anycast nodes.

Set `ACME_CHALLENGE` and `ACME_DNS_PROVIDER` in `install.sh`'s environment and
it writes them into the `.env` it generates, but the credentials file can only
be written after it has unpacked the tree, so it stops there as it does for the
archive storage. Write the file into the install directory it created, then run
`./setup.sh && ./deploy.sh` there rather than `install.sh` again.

Leave both unset for the default HTTP challenge; port 80 also carries the
redirect to HTTPS either way, so keep it published.

Control is configured entirely by `POWER_MANAGE_`-prefixed environment
variables and reads no configuration file. `setup.sh` renders every one of them
into `config/control.env`, and that file is where ordinary settings such as the
log level or the retention windows are edited. `setup.sh` re-renders it on
every run, including through `./deploy.sh`, so re-apply local edits afterwards.

<!-- docref: begin src=deploy/setup.sh#@generated-material:6e3bca0c -->
`setup.sh` creates the internal Ed25519 CA, the control certificate, the
encryption, session and sealing keys, and `config/control.env` with a 90-day
audit-retention policy and the SQLite `POWER_MANAGE_DATABASE_PATH`. It first
refuses, before generating any key material, when `data/backups` shares a
filesystem with `data/control`, because control refuses to start on such a
configuration, and equally when the chosen ACME challenge cannot work — an
unknown `ACME_CHALLENGE`, `dns01` without an `ACME_DNS_PROVIDER`, or
`config/traefik-dns.env` missing, empty, or readable by other accounts. It then
renders the challenge into `config/traefik-acme.env`, and creates an empty
`config/traefik-dns.env` for an `http01` deployment so Compose always has the
file it references. Existing complete keypairs are retained, which permits a
pre-provisioned CA. Partial or unusable material fails closed. Generated secret
files and every file under `config/` are mode 0600, verified before the script
reports success, and no secret value is ever printed.
<!-- docref: end -->

<!-- docref: begin src=deploy/traefik/dynamic/routes.yml#@agent-route:2b16b515,cmd/control/httpserver.go#serveAgent:0543d07f,cmd/control/httpserver.go#buildAgentServer:ccd04d34,internal/agentstream/identity.go#MTLSMiddleware:f1b23680 -->
The public and agent hostnames must differ. Traefik terminates browser/API TLS
for `CONTROL_DOMAIN`. For `AGENT_DOMAIN`, it passes TLS through and adds PROXY
protocol v2 on an isolated network; control itself authenticates the device
certificate and checks revocation.
<!-- docref: end -->

<!-- docref: begin src=deploy/traefik/dynamic/routes.yml#@public-backend-tls:873710ea,deploy/traefik/traefik.yml#@safe-access-log:e383937a -->
Traefik also authenticates control's internal TLS certificate against the
deployment CA, so browser/API traffic stays encrypted after public TLS
termination. Its JSON access log omits the URI-bearing `RequestPath` and
`RequestLine` fields; method, host, status, timing, router, service, and client
metadata remain available without recording query-string credentials.
<!-- docref: end -->

## Start

Run `docker compose up -d --wait`, then inspect the result with
`docker compose ps`.

<!-- docref: begin src=cmd/control/bootstrap_admin.go#runBootstrapAdmin:fd19e1f2,internal/identity/bootstrap.go#Bootstrapper.setupURL:417b204e -->
Create a host-authorized, single-use administrator setup URL:

Run `docker compose exec control control bootstrap-admin`.

The bearer token is placed in the URL fragment, which browsers do not send to
control or Traefik access logs.
<!-- docref: end -->

Use that session to configure OIDC and SCIM. There is no local password or TOTP
administrator.

## Operate

Use `./deploy.sh` for an update, `docker compose logs -f control` for logs, and
`docker compose down` to stop the stack.

Artifacts live under `data/artifacts`, and the audit archive and SQLite backups
under `data/backups` — the separate storage prepared above. The SQLite database
lives under `data/control`; ACME state lives under `data/traefik`. Never
consolidate `data/backups` back onto the database's filesystem: control will
refuse to start after the next restart.

<!-- docref: begin src=internal/maintenance/service.go#Service.RetainAudit:8584f810,cmd/control/config.go#Config.AuditRetention:0e4ab606 -->
Control writes integrity-sealed audit anchors and archive-before-delete chain
prefixes to `POWER_MANAGE_BACKUP_PATH`, and re-verifies every archived prefix
against its recorded checkpoint digest before retention deletes anything more;
`POWER_MANAGE_AUDIT_RETENTION` defaults to 90 days. That path must be a
filesystem of its own, which control enforces at startup; replicating it
off-host is the stronger form of the same property and remains yours to
arrange. Back up the database, artifacts, `certs`, and `secrets` as one
deployment unit.
<!-- docref: end -->

<!-- docref: begin src=cmd/control/config.go#Config.WebhookURL:341af9cf,internal/maintenance/service.go#Service.InspectSecurity:223fcf91,internal/maintenance/service.go#Service.InspectBackup:d8c2e6fd -->
Set the optional `POWER_MANAGE_WEBHOOK_URL` to an HTTPS endpoint to receive
generic security
and backup-lag notifications. The payload contains only the event name and
occurrence time; control has no email or provider-specific notification
integration.
<!-- docref: end -->

<!-- docref: begin src=deploy/backup.sh#@sqlite-backup:99bc90ed,cmd/control/backup_status.go#runBackupStatus:41ed4e6c -->
Run `./backup.sh` from a host timer at least daily. It takes an online SQLite
`.backup`, then verifies the copy with `integrity_check` and `foreign_key_check`
before atomically publishing `backup-status.json`. It retains seven backups by
default and never touches readiness. Inspect the latest success and current lag
with `docker compose exec control control backup-status`;
`POWER_MANAGE_BACKUP_MAX_LAG` defaults to 26 hours.
<!-- docref: end -->

<!-- docref: begin src=internal/store/reads.go#ListDueDeliveries:bbaaa8a0,internal/store/search.go#Search:3244914e -->
Pending dispatch is ordinary SQLite state. Search uses SQLite FTS5. There is no
broker, projector rebuild, dynamic proxy provider, or auxiliary search process
to operate.
<!-- docref: end -->
