# openbao-auditapi — audit-driven secret resync

When a secret is written to OpenBao, force the dependent Kubernetes workloads to
pick up the new value automatically:

```
OpenBao KV write
   │  (HTTP audit device, declarative)
   ▼
audit-resync controller        ← filters to SUCCESSFUL kv writes, derives the ESO key
   │  resolve key → ExternalSecret(s) on the `openbao` store → target Secret
   ▼
ESO resync  (force-sync annotation, or delete the Secret)   ← pulls latest from OpenBao
   ▼
target k8s Secret data changes
   ▼
Stakater Reloader  → restarts the annotated Deployment/StatefulSet
```

## Components

| Path | What |
|---|---|
| `docker-compose.yml` | Local dev harness: dev OpenBao + the controller |
| `config/audit.hcl` | Declarative http audit device → controller |
| `controller/` | The controller (Go, stdlib only, scratch image) |
| `k8s/audit-resync.yaml` | SA + RBAC + Deployment + Service + PDB |
| `k8s/openbao-audit-snippet.hcl` | Audit stanza for the in-cluster OpenBao |

## Why these choices

- **Go, stdlib, async worker.** OpenBao audit is synchronous and *fail-closed* —
  the audit POST is in the critical path of every OpenBao request. The handler
  parses + filters + enqueues and returns `200` immediately; all k8s work runs on
  a debounced background worker with a TTL-cached ExternalSecret index. Queue full
  → drop (a missed trigger is recovered by ESO's `refreshInterval`; blocking
  OpenBao is the worse failure).
- **force-sync over delete.** Annotating the ExternalSecret makes ESO reconcile in
  place — no window where the Secret is missing. `delete` is available via
  `ACTION=delete`. Both trip Reloader (it hashes Secret *data*).
- **Two-layer blast radius.** App allowlist (`ALLOW_NAMESPACES`) + RBAC that grants
  mutation only in `dummyapp`. Plus `DRY_RUN=true` to start.

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `ACTION` | `force-sync` | `force-sync` or `delete` |
| `DRY_RUN` | `true` | log intended action, don't mutate |
| `ALLOW_NAMESPACES` | _(empty=all)_ | only act for real in these namespaces |
| `STORE_NAME` | `openbao` | only act on ExternalSecrets on this store |
| `ESO_API_VERSION` | `v1` | external-secrets.io served version |
| `DEBOUNCE` | `2s` | coalesce repeat writes to the same key |
| `ES_CACHE_TTL` | `15s` | ExternalSecret index cache TTL |

Endpoints: `POST /` (audit sink) · `GET /healthz` · `GET /status` (JSON) · `GET /` (dashboard).

## Local dev

```bash
docker compose up -d --build
# write at a real ESO key path; watch the controller filter + resolve
curl -H 'X-Vault-Token: root' -X POST \
  -d '{"data":{"x":"1"}}' http://127.0.0.1:8200/v1/secret/data/infra/tests/dummyapp
docker compose logs -f controller        # or open http://localhost:9000
```
The local container can't reach the Teleport-fronted cluster, so it runs
`cluster=false` (filter + key derivation only). Real k8s actions happen in-cluster.

## Production runbook (gated)

1. **Image** is built + pushed to ECR automatically by the GitHub Actions
   workflow (keyless via OIDC assuming `Scicom-openbao-hook-ECRAccessRole`):
   `865626945255.dkr.ecr.ap-southeast-5.amazonaws.com/scicom/openbao-hook`.
   Cut a release tag (`git tag vX.Y.Z && git push origin vX.Y.Z`) and the
   workflow publishes `:vX.Y.Z`, `:latest`, `:sha-…`. Same-account EKS nodes pull
   via their node role — no imagePullSecret. The manifest is pinned to `:v0.1.0`.
2. **Deploy the controller first** and wait until Ready (2 replicas):
   ```bash
   kubectl apply -f k8s/audit-resync.yaml
   kubectl -n openbao rollout status deploy/audit-resync
   ```
3. **Wire the audit device** — add `k8s/openbao-audit-snippet.hcl` to the
   in-cluster OpenBao config (keep your existing primary audit device!), then
   restart/SIGHUP OpenBao. ⚠️ Do this only after step 2 is Ready — the device's
   boot-time test POST will crash-loop OpenBao if the controller is unreachable.
4. **Test on dummyapp** (still `DRY_RUN=true`): write to
   `secret/data/infra/tests/dummyapp`, confirm `/status` shows a `would-force-sync`
   for `dummyapp/dummyapp-secrets`.
5. **Go live for dummyapp**: set `DRY_RUN=false`, repeat the write, confirm ESO
   resyncs the Secret and Reloader restarts the `dummyapp` Deployment.
6. **Widen** by adding the `audit-resync-actor` Role+RoleBinding to more namespaces
   and extending `ALLOW_NAMESPACES`.
