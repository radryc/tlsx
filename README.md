# tlsx

Shared TLS/mTLS toolkit for Strata services.

It has two parts:

1. **Go package** (`github.com/radryc/tlsx`) — hot-reloading TLS configs, SPIFFE URI
   SAN verification, and gRPC transport credentials. It is the single TLS
   implementation used by MonoFS, Guardian, Doctor, LB, KVS, and the agent.
2. **`tlsx` CLI** — generates a local CA + one certificate per service and
   installs them as Kubernetes Secrets. This is the "make it work locally" path;
   production PKI can be delivered by cert-manager, Vault, or SPIFFE and mounted
   at the same paths.

## Environment contract

All services read the same variables:

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `STRATA_TLS_MODE` | `off` | `off`, `optional`, `required` |
| `STRATA_TLS_CERT_FILE` | `/var/run/secrets/strata-tls/tls.crt` | leaf certificate |
| `STRATA_TLS_KEY_FILE` | `/var/run/secrets/strata-tls/tls.key` | leaf key |
| `STRATA_TLS_CA_FILE` | `/var/run/secrets/strata-tls/ca.crt` | CA bundle |
| `STRATA_TLS_SERVER_NAME` | | override the dialed server name |
| `STRATA_TLS_REQUIRE_CLIENT_CERT` | `true` | mTLS on servers |
| `STRATA_TLS_ALLOWED_SPIFFE_IDS` | | server-side peer allowlist |
| `STRATA_TLS_EXPECTED_SPIFFE_IDS` | | client-side server allowlist |

Certificates are re-read when the files change, so rotation does not require a
restart.

## Local flow

```bash
# 1. Generate CA + service certs in .tls/ (reuse the CA across runs)
go run ./cmd/tlsx gen --dir .tls --reuse-ca

# 2. Verify chain, keypairs, expiry and SPIFFE SANs
go run ./cmd/tlsx verify --dir .tls

# 3. Install one Secret per service: strata-tls-<service>
go run ./cmd/tlsx install --dir .tls --kubeconfig ~/.kube/config

# 4. Print env for a service (local docker-compose)
go run ./cmd/tlsx env --dir .tls --service monofs-router
```

`gen` also writes `.tls/mtls.env` with per-service path variables and
`.tls/bundle.json` (service → namespace, SPIFFE ID, expiry).

### Kubernetes mount

Each pod mounts its own Secret at the default path:

```yaml
volumes:
  - name: strata-tls
    secret:
      secretName: strata-tls-monofs-router
containers:
  - name: router
    volumeMounts:
      - name: strata-tls
        mountPath: /var/run/secrets/strata-tls
        readOnly: true
    env:
      - name: STRATA_TLS_MODE
        value: required
      - name: STRATA_TLS_ALLOWED_SPIFFE_IDS
        value: spiffe://strata.local/ns/monofs/sa/monofs-server,spiffe://strata.local/ns/monofs/sa/monofs-search
```

### Docker Compose mount

```yaml
services:
  monofs-router:
    volumes:
      - ./.tls/monofs-router:/var/run/secrets/strata-tls:ro
    environment:
      STRATA_TLS_MODE: required
```

## Package usage

```go
env, err := tlsx.LoadEnv()
if err != nil { return err }

// gRPC server
creds, err := tlsx.ServerCredentials(env.ServerConfig())
srv := grpc.NewServer(grpc.Creds(creds))

// gRPC client (mTLS)
creds, err = tlsx.ClientCredentials(env.ClientConfig())
conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
```

`VerifyPeerSPIFFE` is applied automatically when an allowlist is configured.

## Production

Generated certificates are for development and bootstrap. In production:

- issue short-lived certs from cert-manager or Vault,
- mount them at `/var/run/secrets/strata-tls/{tls.crt,tls.key,ca.crt}`,
- set `STRATA_TLS_MODE=required` and the SPIFFE allowlists,
- keep the same environment contract — no code changes.

The generated CA key (`ca.key`) is sensitive. Do not commit `.tls/`; it is
ignored by `.gitignore`.
