# route53-dnsweaver-webhook

A small Go service that plugs [dnsweaver](https://github.com/maxfield-allison/dnsweaver)
into AWS Route53. dnsweaver already does the hard part — watching the
Docker socket, parsing Traefik/Caddy/nginx-proxy labels (or its own
`dnsweaver.*` labels), and reconciling desired vs. live DNS state — but it
doesn't ship a Route53 backend. This service implements dnsweaver's generic
`webhook` provider contract so dnsweaver can drive Route53 directly.

```text
Docker containers (Traefik/Caddy/nginx-proxy labels, or dnsweaver.* labels)
        │  watches Docker events
        ▼
    dnsweaver  ──── GET /ping, /list · POST /create · PUT /update · DELETE /delete ────►  this webhook
                                                                                              │
                                                                                              ▼
                                                                                        AWS Route53
```

## Why a webhook instead of a from-scratch tool

dnsweaver already handles the parts that are easy to get wrong: debouncing
Docker events, matching hostnames against domain patterns, split-horizon
routing, TXT ownership records, and Swarm support. Writing a Route53
*provider* for it is a couple hundred lines against a documented JSON
contract; writing a whole new label-watcher would be reinventing that.

## What this does

- Implements `GET /ping`, `GET /list`, `POST /create`, `PUT /update`,
  `DELETE /delete` exactly as dnsweaver's webhook client calls them.
- Supports `A`, `AAAA`, `CNAME`, `TXT`, and `SRV` records. `CNAME` and `SRV`
  targets are stored dot-terminated, which is the form Route53 hands back on
  the next `/list`, so a value doesn't change shape on round trip.
- Uses Route53 `UPSERT` for create/update, so repeated reconciliation
  (e.g. on dnsweaver restart) is idempotent.
- Looks up the existing record before deleting (Route53 requires an exact
  name/type/value match for `DELETE` changes) and treats deleting an
  absent record as success.
- Validates every request before it reaches Route53: hostname shape, `A`/
  `AAAA` values as real IP addresses, TTL bounds, and body size. Wildcards
  are only accepted as a whole leftmost label, since that is the only place
  Route53 treats `*` as a wildcard rather than a literal character, so
  `prod*.example.com` is a `400` here instead of a record that resolves for
  nothing.
- Optional shared-secret header check, matching dnsweaver's own
  `AUTH_HEADER`/`AUTH_TOKEN` webhook config. The header name and token
  must be configured together; setting only one is a startup error rather
  than a silently unprotected endpoint.
- Standard AWS SDK credential chain (env vars, shared config/profile,
  EC2/ECS instance role) — no AWS keys hardcoded or required.
- Graceful shutdown on `SIGTERM`/`SIGINT`, so in-flight Route53 changes
  finish before the process exits.
- Every request gets a request ID, a structured JSON access-log line, and a
  panic guard that still answers in dnsweaver's error shape.

## Records it deliberately ignores

`GET /list` skips, `DELETE /delete` refuses to touch, and `POST /create` and
`PUT /update` refuse to overwrite any record set that can't be expressed as a
flat hostname/type/value triple:

- Alias records (Route53 alias-to-ELB/CloudFront/S3).
- Routing-policy records — weighted, latency, geolocation, failover, and
  multivalue-answer records, identified by their `SetIdentifier`.
- Traffic-policy instances.
- Record types outside `A`, `AAAA`, `CNAME`, `TXT`, `SRV` (so `NS`, `SOA`,
  `MX`, `CAA` and friends are left alone).
- `TXT` record sets Route53 stores as several quoted strings, which is what
  it does to any value over 255 bytes. Listing one would concatenate the
  segments into a value a write could never reproduce.
- `SRV` rdata that isn't the four fields this contract expects (priority,
  weight, port, target). Reporting one as a bare string would advertise a
  record that fails validation the moment anything writes it back.

Without this, dnsweaver would see an alias record as an `A` record with an
empty value and "repair" it into a plain record, destroying the alias.

The write side matters as much as the read side, and for the same reason.
Hiding an alias from `/list` is exactly what makes dnsweaver believe the
hostname has no record and ask for one to be created, and a bare Route53
`UPSERT` replaces whatever already sits at that name and type. So a write
checks the target first and answers `409` rather than clobbering it. That
costs one extra Route53 lookup per create or update; `DELETE` already paid
for the same lookup.

## What it doesn't do (yet)

- Multiple hosted zones per instance (run one instance per zone if you
  need more than one; dnsweaver supports multiple provider instances).
- Create alias records. Point a `CNAME` at the ELB DNS name instead, or
  extend `recordValue` to build an `AliasTarget` when the value looks like
  an AWS resource DNS name.
- TXT values over 255 bytes (Route53 requires splitting those into
  multiple quoted segments). Such values are rejected with a `400`, and
  existing ones are hidden rather than misreported.
- Multi-value record sets are listed as one entry per value, but a
  create/update writes a single value and replaces the whole set.

## Setup

### 1. IAM policy

Scope this to the specific hosted zone:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
      "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHI"
    },
    {
      "Effect": "Allow",
      "Action": ["route53:GetHostedZone"],
      "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHI"
    }
  ]
}
```

### IAM roles: works wherever you run it, no keys required

This service never *requires* a static access key. It uses the AWS SDK
v2's standard default credential chain, which already covers every common
IAM-role mechanism - pick whichever row matches your environment, no code
or extra config needed:

| Where it runs                                         | Mechanism                            | Setup                                                                                                                                                                                                                       |
|-------------------------------------------------------|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| EC2 instance                                          | Instance profile (IMDS)              | Attach the policy above to the instance's IAM role. Nothing else to configure.                                                                                                                                              |
| ECS / Fargate task                                    | Task role                            | Attach the policy above to the task role. The container credentials endpoint is injected automatically.                                                                                                                     |
| EKS, IRSA                                             | Web identity federation              | Attach the policy above to an IAM role trusted by your cluster's OIDC provider; annotate the service account with that role ARN. EKS's pod-identity webhook injects `AWS_ROLE_ARN` / `AWS_WEB_IDENTITY_TOKEN_FILE` for you. |
| EKS Pod Identity (newer)                              | Container credentials endpoint       | Associate the pod identity in EKS; credentials are injected the same way as ECS.                                                                                                                                            |
| Self-hosted / non-EKS Kubernetes with OIDC federation | Web identity federation              | Same mechanism as IRSA - it's not EKS-specific. Set `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` (pointing at a projected service account token) yourself if your cluster doesn't inject them automatically.            |
| Local dev / anywhere else                             | Shared config profile or static keys | `AWS_PROFILE` against a mounted `~/.aws/config`, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` as a last resort.                                                                                                           |

If you need cross-account access (the hosted zone lives in a different
account than the role above), that's also handled by the standard chain:
add a `[profile ...]` block with `role_arn` + `source_profile` (or
`credential_source`) to the shared config file, or set `AWS_PROFILE` to
point at it. No code in this service needs to know about it.

### 2. Build and run

Released images are published to GHCR for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/goodmannershosting/route53-dnsweaver-webhook:latest
```

Tags are `1.2.3`, `1.2`, `1` and `latest`, so you can pin at whichever level
of churn you're willing to accept. Or build it yourself:

```bash
goreleaser release --snapshot --clean --skip=archive,nfpm,sbom,sign
```

That's GoReleaser rather than `docker build` because the Dockerfile copies a
binary GoReleaser has already compiled instead of compiling its own — see
[Releases](#releases). A snapshot build loads one image per architecture into
your local daemon, tagged with a `-amd64` or `-arm64` suffix.

The image is a static binary on `distroless/static`, so there's no shell or
package manager in it, and it runs as `nonroot`. That also means you can't
`docker exec` into it to debug — read the JSON logs on stdout instead.

If you'd rather run it on a bare host, each release also carries `.deb`, `.rpm`
and `.apk` packages for every Linux architecture, plus plain tarballs for
Linux, macOS and Windows:

```bash
sudo dpkg -i route53-dnsweaver-webhook_1.0.0_amd64.deb
sudoedit /etc/default/route53-dnsweaver-webhook   # hosted zone id, shared secret
sudo systemctl enable --now route53-dnsweaver-webhook
```

The package puts the binary in `/usr/bin`, the unit in
`/usr/lib/systemd/system` and a root-only (mode 0600) environment file in
`/etc/default/route53-dnsweaver-webhook`, marked as a config file so upgrades
leave your settings alone. It isn't enabled on install: without a hosted zone
id the service can only fail, so enabling it is your call once it's
configured.

The unit runs under `DynamicUser=yes`, which means there's no service account
to create and nothing on disk it can write. The one consequence worth knowing:
if you set `WEBHOOK_AUTH_TOKEN_FILE` instead of putting the token in the
environment file, the dynamic user won't be able to read that file without a
`SupplementaryGroups=` drop-in. systemd reads the environment file as root
before dropping privileges, so a secret in there is fine.

Or use the included `docker-compose.example.yml`, which wires up Traefik +
dnsweaver + this webhook + two sample containers (one using plain Traefik
labels with a stack-wide default target, one overriding its target
per-container via `dnsweaver.records.*` labels). Generate the shared secret
first:

```bash
mkdir -p secrets && openssl rand -hex 32 | tr -d '\n' > secrets/webhook_token.txt
docker compose -f docker-compose.example.yml up -d
```

`secrets/` is gitignored. The webhook publishes no ports — only dnsweaver
reaches it, over an internal compose network.

### 3. Configure dnsweaver to use it

```yaml
environment:
  - DNSWEAVER_INSTANCES=route53
  - DNSWEAVER_ROUTE53_TYPE=webhook
  - DNSWEAVER_ROUTE53_URL=http://route53-webhook:8080
  - DNSWEAVER_ROUTE53_AUTH_HEADER=X-Webhook-Token
  - DNSWEAVER_ROUTE53_AUTH_TOKEN_FILE=/run/secrets/webhook_token
  - DNSWEAVER_ROUTE53_DOMAINS=*.example.com
  - DNSWEAVER_ROUTE53_RECORD_TYPE=A
  - DNSWEAVER_ROUTE53_TARGET=203.0.113.10
```

## Configuration (this webhook)

Settings come from flags, environment variables and an optional config file,
resolved by [viper](https://github.com/spf13/viper) in that order of
precedence. Run `--help` for the generated flag list.

| Flag                 | Environment variable                                                            | Required | Description                                                                                                                                    |
|----------------------|---------------------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `--hosted-zone-id`   | `ROUTE53_HOSTED_ZONE_ID`                                                        | yes      | Hosted zone to manage (`Z...`, with or without the `/hostedzone/` prefix).                                                                     |
| `--default-ttl`      | `ROUTE53_DEFAULT_TTL`                                                           | no       | Fallback TTL in seconds when dnsweaver doesn't send one. Default `300`.                                                                        |
| `--port`             | `PORT`                                                                          | no       | Listen port. Default `8080`.                                                                                                                   |
| `--auth-header`      | `WEBHOOK_AUTH_HEADER`                                                           | no       | Header name to check on incoming requests, e.g. `X-Webhook-Token`. Required if a token is set.                                                 |
| `--auth-token-file`  | `WEBHOOK_AUTH_TOKEN_FILE`                                                       | no       | File holding the shared secret, Docker-secrets style. An unreadable path is a startup error, not a silent fallback.                            |
| *(none — see below)* | `WEBHOOK_AUTH_TOKEN`                                                            | no       | The shared secret itself. Must match `DNSWEAVER_ROUTE53_AUTH_TOKEN` on the dnsweaver side. Required if a header name is set.                   |
| `--log-level`        | `LOG_LEVEL`                                                                     | no       | `debug`, `info`, `warn` or `error`. Default `info`.                                                                                            |
| `--config`           | —                                                                               | no       | Path to a config file. Without it, `./config.yaml` and `/etc/route53-dnsweaver-webhook/config.yaml` are tried and it's fine if neither exists. |
| `--version`          | —                                                                               | no       | Print the version stamped in at build time and exit. Answers before any validation, so it works on an otherwise unconfigured host.             |
| —                    | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, etc. | —        | Standard AWS SDK v2 credential/region resolution — see the IAM roles section above.                                                            |

There is deliberately **no `--auth-token` flag**. Process arguments are
readable by every user on the host through `ps`, so the secret only comes
from the environment, a file, or the config file.

A config file uses the flag names as keys:

```yaml
# config.yaml
hosted-zone-id: Z0123456789ABCDEFGHI
default-ttl: 300
port: 8080
auth-header: X-Webhook-Token
auth-token-file: /run/secrets/webhook_token
log-level: info
```

If you put the token directly in a config file rather than a separate secret
file, make sure the file isn't world-readable.

## Layout

Standard Go project layout — one binary under `cmd/`, everything else
unimportable from outside the module under `internal/`:

```shell
cmd/route53-dnsweaver-webhook/   process wiring: config, logger, signals
internal/config/                 flag/env/file resolution and validation
internal/route53/                the DNS provider: records in, Route53 out
internal/api/                    chi router, middleware, webhook handlers
```

`internal/api` depends on `internal/route53` for the record types and talks
to it through a `Provider` interface it declares itself, so the handlers can
be tested against a fake with no AWS credentials. The provider wraps
validation failures in `route53.ErrInvalid` and refusals to overwrite zone
state in `route53.ErrConflict`, which is how the API layer picks between
`400`, `409` and `502` without duplicating the rules.

## Per-container DNS targets

Since you want the target to vary per container rather than be fixed for
the whole stack, use dnsweaver's own generic label source alongside (or
instead of) Traefik labels:

```yaml
labels:
  - dnsweaver.records.myapp.hostname=myapp.example.com
  - dnsweaver.records.myapp.type=A        # or CNAME, AAAA, TXT, SRV
  - dnsweaver.records.myapp.target=203.0.113.42
  - dnsweaver.records.myapp.ttl=60        # optional, defaults to ROUTE53_DEFAULT_TTL
```

Or, for the simple case (one hostname per container, default type/target
from the dnsweaver instance config):

```yaml
labels:
  - dnsweaver.hostname=myapp.example.com
```

Both label styles, and Traefik/Caddy/nginx-proxy labels, can coexist on
different containers in the same stack — dnsweaver merges all configured
sources.

## Testing without Docker

```bash
go test ./...
```

The unit tests cover configuration precedence (flag over environment over
file), the auth check, every handler against a fake provider, the provider
against a fake Route53 API, and record conversion — none of which need AWS
credentials. There's no integration test against a live Route53 zone
included — test against a scratch/sandbox hosted zone before pointing this
at production DNS.

## CI and dependency updates

`.github/workflows/ci.yml` runs on every push to `main`, every pull request,
and weekly on a schedule so the security jobs still catch newly disclosed
vulnerabilities in code that hasn't changed. Four jobs run in parallel:

- `Test` — gofmt, a `go mod tidy` diff check, `go vet`, `go build`, then
  `go test -race -shuffle=on` with a coverage summary.
- `Lint` — golangci-lint using `.golangci.yml`.
- `Vulnerability scan` — `govulncheck`, which reports only vulnerabilities
  actually reachable from this code rather than everything in the module
  graph.
- `Container image` — builds the image through GoReleaser, exactly as a
  release does, then starts it with a throwaway token and no AWS credentials
  and asserts that an unauthenticated `GET /ping` returns `401`. The runtime
  image is distroless, so there's no shell to debug a bad build after the
  fact; this catches an image that builds but can't boot. Because it runs
  GoReleaser, it also fails on a broken `.goreleaser.yaml` rather than leaving
  that to discover at release time.

The golangci-lint and govulncheck versions are pinned in the workflow rather
than tracking latest, so a tool release can't turn an unrelated pull request
red. Bump them deliberately when you want the new checks. Pinning govulncheck
doesn't blind it to new advisories: the vulnerability database is fetched at
run time, and only the binary is fixed.

Every action is pinned to a full commit SHA rather than a tag, because tags
are mutable and the action owner can silently repoint them, which is how the
`trivy-action` and `kics-github-action` compromises worked. The trailing
`# v1.2.3` comment isn't decoration: Dependabot reads it to work out the
semver of a SHA pin, and updates the SHA and the comment together. The
Dockerfile's base image is pinned the same way, by digest with the tag kept
alongside for readability.

Dependabot (`.github/dependabot.yml`) watches Go modules, action versions and
the Dockerfile base images weekly. Minor and patch updates are batched into a
few grouped pull requests; majors are excluded from every group so they
arrive individually. Every ecosystem has a cooldown, so a release has to sit
for a few days before Dependabot picks it up — a compromised or broken
version is usually yanked well within that window, and nothing here needs to
be first to a new release. Security updates ignore cooldown.

### Auto-merge

`.github/workflows/dependabot-automerge.yml` approves Dependabot pull
requests and queues them with `gh pr merge --auto` when the update is minor
or patch. Majors get a comment instead and wait for a human.

Two repository settings have to be in place, and the second one is the one
that matters:

1. Settings, then General, then Pull Requests: enable "Allow auto-merge".
   Without it `gh pr merge --auto` errors out.
2. Require the CI checks on `main`. `--auto` only queues the merge; branch
   protection is what actually holds the pull request until CI passes. With
   no required checks configured, auto-merge lands the update immediately
   and the tests become decoration.

```bash
gh api -X PUT repos/GoodMannersHosting/route53-dnsweaver-webhook/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Test", "Lint", "Vulnerability scan", "Container image"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

That `PUT` writes the entire protection rule, so treat it as a one-time
bootstrap rather than something to re-run. The nulls above are not
placeholders for "leave alone" — replaying it later clears any review
requirement or push restriction added in the meantime. Once the branch is
protected, change the required checks on their own:

```bash
gh api -X PATCH \
  repos/GoodMannersHosting/route53-dnsweaver-webhook/branches/main/protection/required_status_checks \
  --input - <<'EOF'
{
  "strict": true,
  "contexts": ["Test", "Lint", "Vulnerability scan", "Container image"]
}
EOF
```

The auto-merge workflow triggers on `pull_request` rather than
`pull_request_target`, and never checks out the repository. It runs with
write permissions, so it deliberately never executes any code from the
branch it's merging.

## Releases

Publishing a GitHub Release creates the tag and triggers
`.github/workflows/release.yml`. Draft the notes in the UI first; GoReleaser
appends its generated changelog rather than replacing what you wrote.

One job does everything, driven by `.goreleaser.yaml`. It builds static
binaries for Linux (amd64, arm64, armv7, 386), macOS (amd64, arm64) and
Windows (amd64, arm64), wraps them in tarballs — zip files on Windows — turns
each Linux build into a `.deb`, `.rpm` and `.apk`, and uploads all of it with a
`checksums.txt`. Builds are reproducible: `mod_timestamp` pins the embedded
timestamp to the commit, so the same commit produces the same bytes.

The container image comes out of the same run. GoReleaser's `dockers_v2`
drives `docker buildx` to push a `linux/amd64` and `linux/arm64` manifest to
`ghcr.io/goodmannershosting/route53-dnsweaver-webhook`, and the Dockerfile
copies the binaries already built above rather than compiling its own. That
matters for more than speed: the container and the tarball now contain
identical bytes, so a signature or SBOM published for one describes the other.
Building inside the image, as this repo used to, meant a second compile under
the base image's Go toolchain, which drifts from the version in `go.mod`.

The tradeoff is that `docker build .` no longer works on its own, since the
build context is a temporary directory GoReleaser assembles. Build the image
locally with `goreleaser release --snapshot --clean --skip=archive,nfpm,sbom,sign`,
which is also what CI does before its smoke test.

Note that `dockers_v2` is still marked experimental upstream and is slated to
replace `dockers` in GoReleaser v3, so expect a config rename eventually.

### Provenance, signatures and SBOMs

Every release artifact carries three things beyond the artifact itself.

A build provenance attestation from GitHub, which says which repository,
workflow and commit produced the file:

```bash
gh attestation verify route53-dnsweaver-webhook_1.0.0_linux_amd64.tar.gz \
  --repo GoodMannersHosting/route53-dnsweaver-webhook

gh attestation verify \
  oci://ghcr.io/goodmannershosting/route53-dnsweaver-webhook:1.0.0 \
  --repo GoodMannersHosting/route53-dnsweaver-webhook
```

A keyless cosign signature, which says who signed it. There's no private key
anywhere in the repo or its secrets: the release workflow's own OIDC identity
is the signer, and Sigstore issues it a certificate that lives for a few
minutes. Each artifact gets its own `<artifact>.bundle` holding the signature,
that certificate and the transparency log entry, so one archive can be checked
without downloading the rest of the release:

```bash
cosign verify-blob \
  --bundle route53-dnsweaver-webhook_1.0.0_linux_amd64.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/GoodMannersHosting/route53-dnsweaver-webhook/\.github/workflows/release\.yml@' \
  route53-dnsweaver-webhook_1.0.0_linux_amd64.tar.gz

cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/GoodMannersHosting/route53-dnsweaver-webhook/\.github/workflows/release\.yml@' \
  ghcr.io/goodmannershosting/route53-dnsweaver-webhook:1.0.0
```

The image signature is made against the digest rather than a tag, so it
follows the bytes even after `latest` moves; verifying by tag works because
cosign resolves the tag to that digest first.

And an SBOM listing the Go modules compiled into that build, as SPDX 2.3 JSON
produced by [syft](https://github.com/anchore/syft). Archives and packages get
a plain `<artifact>.sbom.json` file on the release, signed like everything
else. The image gets two: BuildKit attaches its own SBOM to the manifest
index, which is convenient for registry tooling but unsigned, and the workflow
adds a signed attestation per architecture on top, attached to that
architecture's manifest. The signed ones are per-architecture because syft
resolves a multi-arch index to whichever platform it happens to be running on:

```bash
digest=$(docker buildx imagetools inspect \
  ghcr.io/goodmannershosting/route53-dnsweaver-webhook:1.0.0 \
  --format '{{ json .Manifest }}' \
  | jq -r '.manifests[] | select(.platform.architecture == "amd64") | .digest')

cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/GoodMannersHosting/route53-dnsweaver-webhook/\.github/workflows/release\.yml@' \
  "ghcr.io/goodmannershosting/route53-dnsweaver-webhook@${digest}"
```

The workflow pins syft and cosign to specific versions, because the arguments
in `.goreleaser.yaml` are version-specific — cosign 3 dropped the separate
`--output-signature`/`--output-certificate` flags that cosign 2 used in favour
of the bundle above.

The version is stamped into the binary at link time, so a running container
can tell you what it is. It appears in the startup log line and via the flag:

```bash
docker run --rm ghcr.io/goodmannershosting/route53-dnsweaver-webhook:latest --version
```

A plain `go build` reports `dev`; a snapshot build reports something like
`0.0.0-SNAPSHOT-6031241`, since GoReleaser stamps the version through
`-ldflags` for the image and the archives alike.

The generated changelog groups commits by the prefixes used elsewhere in the
repo: `feat`, `fix`, and the `deps`/`ci`/`docker` prefixes Dependabot is
configured to write, so auto-merged updates land in one section instead of
scattering through the notes.

The first release needs one manual step. A brand-new GHCR package is private,
so after publishing v0.1.0 go to the package settings and either make it
public or grant pull access to whoever needs it.

## Deployment notes

- Auth is a shared bearer secret over whatever transport you put it
  behind. Keep the webhook on an internal network, or terminate TLS in
  front of it; the token is otherwise sent in clear text.
- There's no rate limiting. The auth token and network placement are the
  only things standing between a caller and your zone, so scope the IAM
  policy to the single hosted zone as shown above.
- Upstream AWS errors are logged, not returned. Clients get a generic
  `502`/`503`; check the service logs for the Route53 error and request
  ID.
- Shutdown waits up to 35 seconds so an in-flight Route53 call can finish,
  which is longer than the 10 seconds Docker grants by default. Give the
  container a matching `stop_grace_period`, as the compose example does, or
  it gets `SIGKILL`ed mid-drain.
