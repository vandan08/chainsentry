# GitHub App Setup

How to register and wire the ChainSentry GitHub App (Phase 3).

## 1. Register the App

GitHub → Settings → Developer settings → **GitHub Apps** → New GitHub App.

| Field | Value |
|---|---|
| Name | `chainsentry-dev-<yourname>` (App names are global-unique) |
| Homepage URL | your repo URL |
| Webhook URL | `https://<tunnel>/webhooks/github` (see ngrok below) |
| Webhook secret | generate: `openssl rand -hex 32` — goes into `CHAINSENTRY_GITHUB_WEBHOOK_SECRET` |

### Permissions (least privilege — be ready to justify each in an interview)

| Permission | Level | Used for |
|---|---|---|
| Checks | Read & write | Creating Check Runs with pass/fail + annotations |
| Contents | Read-only | Cloning the repo to scan |
| Pull requests | Read & write | SBOM-diff summary comments |
| Metadata | Read-only | Mandatory baseline |

### Subscribe to events
`pull_request`, `push`, `installation`, `installation_repositories`

## 2. Keys & secrets

After creation:
1. **Generate a private key** (.pem) — used to sign the App JWT. Store outside the repo; path via `CHAINSENTRY_GITHUB_PRIVATE_KEY_PATH`.
2. Note the **App ID** → `CHAINSENTRY_GITHUB_APP_ID`.
3. Never commit the .pem or webhook secret (already covered by `.gitignore`).

Local config goes in `backend/src/main/resources/application-local.yml` (gitignored):

```yaml
chainsentry:
  github:
    app-id: 123456
    private-key-path: C:/Users/admin/keys/chainsentry-dev.pem
    webhook-secret: <hex secret>
```

## 3. Token flow (implemented in the `github` module)

```
App private key ──signs──▶ JWT (10 min, iss = App ID)
JWT ──POST /app/installations/{id}/access_tokens──▶ installation token (1 h)
installation token ──▶ clone, Checks API, PR comments
```

Cache installation tokens until ~5 min before expiry. Never log tokens.

## 4. Local webhook development

GitHub must reach your machine — you already have ngrok:

```powershell
ngrok http 8080
```

Put the `https://….ngrok-free.app/webhooks/github` URL in the App settings. The App settings → **Advanced** tab shows recent deliveries with payloads and lets you **redeliver** — the main debugging loop.

## 5. Verify every delivery

- Compute HMAC-SHA256 of the raw body with the webhook secret; constant-time-compare against `X-Hub-Signature-256`. Reject on mismatch **before** parsing JSON.
- Dedupe on `X-GitHub-Delivery` GUID (GitHub redelivers).
- Respond 2xx fast (< 10 s limit): verify, persist, enqueue — process async.

## 6. Test drive

1. Install the App on a scratch repo (create one with a deliberately vulnerable `pom.xml` — log4j-core 2.14.1 is the classic).
2. Open a PR → webhook arrives → scan runs → Check Run + comment appear.
3. This scratch repo doubles as the **permanent demo repo** — keep it.
