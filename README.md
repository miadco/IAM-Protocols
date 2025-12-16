
# IAM Protocols (Microsoft Entra ID, OAuth 2.0, OpenID Connect, JWT) 🔐

## Recruiter Quick Scan 👀

- Built **OIDC sign-in** (authorization code flow) with **Flask + MSAL** and rendered **ID token claims** ✅
- Called **Microsoft Graph** with a **delegated access token** (`scp`) to retrieve user profile data (`GET /v1.0/me`) 🧾
- Built a **headless daemon** using **client credentials** with **application permissions** (`roles`) to read users and sign-in logs 🤖
- Implemented a **protected resource server** (custom Flask API) validating JWTs via **Entra JWKS** and enforcing **aud/iss/scope** 🛡️
- Demonstrated correct API behavior for **401 vs 403** (missing/invalid token vs valid token missing scope) 🚦

---

A hands-on, code-first lab series proving real IAM patterns with **Microsoft Entra ID** and **Python (Flask + MSAL)** 🐍.

Each lab produces a working outcome you can run locally and validate with screenshots and live token inspection 📸.

---

## What this repo proves 🎯

- **OIDC authentication** with Entra ID (ID token claims) 🔑
- **OAuth delegated authorization** to Microsoft Graph (`scp` scopes) 👤
- **OAuth app-only automation** using client credentials (`roles` application permissions) ⚙️
- **Resource server protection** for a custom API using JWT bearer validation (JWKS, `aud`, `iss`, scopes) 🔒

---

## Labs (run order) 🧪

| Lab | Outcome you can verify | Tokens and claims | Folder |
|---:|---|---|---|
| 1 | Sign in with Microsoft and view **ID token claims** in the app | `id_token` (JWT) | [Lab 1](./Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/) |
| 2 | Acquire delegated **access token** and call Graph `GET /me` | access token with `scp=User.Read` | [Lab 2](./Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/) |
| 3 | Run a headless daemon that calls Graph `GET /users` and `GET /auditLogs/signIns` | access token with `roles=User.Read.All, AuditLog.Read.All` | [Lab 3](./Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/) |
| 4 | Call a protected API `/data` and confirm correct **401 vs 403** behavior | access token with `aud=api://...` and `scp=Data.Read` | [Lab 4](./Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/) |

---

## Architecture mental model 🧠

```mermaid
flowchart LR
  U[User] -->|Browser sign-in| Entra[Microsoft Entra ID]
  Entra -->|auth code| WebApp[Lab 1/2 Flask App]
  WebApp -->|token exchange| Entra
  WebApp -->|access token| Graph[Microsoft Graph]

  Daemon[Lab 3 Python Daemon] -->|client credentials| Entra
  Daemon -->|app-only access token| Graph

  Client[Lab 4 Client] -->|delegated token request| Entra
  Client -->|Bearer token| API[Lab 4 Protected Flask API]
  API -->|JWKS fetch| JWKS[Entra JWKS]
````

---

## Proof artifacts (what I capture) 📌

Across the labs, I capture evidence that the IAM behavior worked:

* App registration configuration (redirect URI, API permissions, exposed scopes) 🧩
* Consent and admin consent states ✅
* Token inspection screenshots (jwt.ms checks for `aud`, `scp`, `roles`) 🔎
* Terminal output proving successful API calls and expected failures (401/403) 🖥️

Each lab folder includes a `screenshots/` directory and a README with step-by-step reproduction 🧾.

---

## Key IAM distinctions demonstrated 📚

### ID token vs access token 🔁

* **ID token** answers: *Who is the user?* (OIDC, authentication) 🪪
* **Access token** answers: *What can this caller access?* (OAuth, authorization) 🎫

### Delegated vs application permissions 🧷

* **Delegated permissions**: app acts *on behalf of a user* (`scp`) 👤
* **Application permissions**: app acts *as itself* (`roles`) and requires **admin consent** 🏛️

### 401 vs 403 (resource server behavior) 🚧

* **401 Unauthorized**: missing/invalid token or malformed Authorization header ⛔
* **403 Forbidden**: token is valid but missing required scope/permission 🚫

---

## Security notes 🔐

* Secrets are never committed:

  * Lab 1 uses `config.py` locally (gitignored) and commits only `config_example.py` 🧾
  * Labs 3–4 use `.env` locally (gitignored) 🌱
* For production, I would replace shared secrets with:

  * certificate-based auth, managed identity, and a secret manager (for example, Key Vault) 🗝️

---

## How to use this repo 🧭

1. Start at **Lab 1** and move forward in order.
2. Follow the README in each lab folder.
3. Validate success conditions (token claims + API responses).
4. Use the screenshots as proof for portfolio and interviews.

---

## Acknowledgments 🙏

These labs use AI-assisted development as a learning accelerator.

AI helped with implementation patterns, structure, and debugging guidance.
I own the tenant configuration, troubleshooting decisions, and can explain each flow, claim, and security tradeoff.
