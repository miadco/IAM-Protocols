# IAM Protocols – Lab 4: Protect a Custom API with JWT Bearer Tokens (Resource + Client)

## Learning Objectives

By the end of this lab, I will be able to:

* Explain the difference between Microsoft Graph as a resource and a custom API as a resource.
* Expose a custom API in Microsoft Entra ID with a custom scope (Data.Read).
* Implement JWT bearer token validation in a Python Flask API using Entra JWKS.
* Configure a client app to request an access token for a custom scope.
* Call a protected API with an access token from MSAL and handle 401 and 403 responses.
* Troubleshoot common JWT validation problems such as bad JWKS URLs, audience mismatches, and missing Authorization headers.

---

## 📌 Overview

Labs 1 through 3 all used Microsoft Graph as the resource:

* Lab 1 proved I could sign in with OpenID Connect and get an ID token.
* Lab 2 used delegated permissions to call Microsoft Graph on behalf of a user.
* Lab 3 used application permissions and the client credentials flow to call Microsoft Graph as a daemon.

In **Lab 4**, I move beyond Graph and protect my **own** API.

* I build a Python Flask API that exposes a `/data` endpoint on `http://localhost:5000`.
* I register that API as an application in Microsoft Entra ID and expose a custom scope:
  `api://<protected-api-client-id>/Data.Read`
* I configure a separate client app that requests an access token for this custom scope.
* The Flask API validates incoming JWT bearer tokens against Entra’s JWKS endpoint, checking:

  * Signature
  * Issuer
  * Audience
  * Scope (Data.Read)

The point of this lab is to prove that I understand how to:

* Turn a plain Flask API into an **OAuth 2.0 protected resource**.
* Wire it up to Entra so only callers with the right access token and scope can reach `/data`.
* Debug real-world JWT validation errors (bad JWKS URL, wrong issuer, wrong audience, missing Authorization header).

---

## 🎯 Objectives

By the end of this lab I have:

* Registered a **Lab4-ProtectedApi** app registration in Microsoft Entra ID.
* Configured an **Application ID URI** and exposed a custom delegated scope:

  * `Data.Read`
* Registered a separate **Lab4-ClientApp** and:

  * Added delegated permission `Data.Read` from the Lab4-ProtectedApi.
  * Granted consent so the client can request that scope.
* Implemented a Flask API that:

  * Loads `TENANT_ID`, `API_AUDIENCE`, and `JWKS_URL` from `.env`.
  * Uses `PyJWKClient` and `jwt` to validate incoming tokens.
  * Returns:

    * `200 OK` with JSON data when the token is valid and has `Data.Read`.
    * `401` with `WWW-Authenticate: Bearer ...` when the header is missing or malformed.
    * `403` when the token is valid but does not have the required scope.
* Implemented a Python client script (`client_delegated.py`) that:

  * Uses MSAL to get a delegated access token for the `Data.Read` scope.
  * Calls `http://localhost:5000/data` with `Authorization: Bearer <token>`.
* Verified behavior with:

  * The client script returning `Status: 200`.
  * `curl` without a token returning `401` with a helpful `WWW-Authenticate` header.

---

## 🧠 Key Concepts

### Custom Resource vs Microsoft Graph

* In Labs 1–3, `aud` in the token was `https://graph.microsoft.com`.
* In Lab 4, I define my own **API audience**:
  `api://<Lab4-ProtectedApi-client-id>`
* My Flask API uses that audience to decide whether a token is intended for it.

### Exposing an API and Custom Scopes

* **Expose an API** in Entra gives my app an **Application ID URI**.
* I add a custom **delegated permission** (scope) named `Data.Read`.
* The client app must request this exact scope:

  * `api://<Lab4-ProtectedApi-client-id>/Data.Read`

### JWT Bearer Validation

The API must validate incoming tokens by checking:

* Signature: using Entra’s JWKS keys from
  `https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys`
* Issuer: `https://login.microsoftonline.com/{TENANT_ID}/v2.0`
* Audience: my custom `API_AUDIENCE`.
* Scope: `scp` claim includes `Data.Read`.

If any of these fail, the API returns an appropriate 401 or 403.

### JWKS (JSON Web Key Set)

* Entra publishes public keys at the JWKS endpoint.
* `PyJWKClient` downloads the keys and matches on the `kid` in the JWT header.
* Using the wrong URL for JWKS triggers errors such as
  `PyJWKClientConnectionError: HTTP Error 400: Bad Request`.

### HTTP 401 vs 403

* `401 Unauthorized`
  The request is not authenticated correctly (for example, missing Authorization header, malformed token).
* `403 Forbidden`
  The token is valid, but the caller does not have the required scope or role.

---

## 🧠 Mental Model

I treat Lab 4 as a three-party conversation:

1. **User + Client App**

   * The user signs in and consents to the `Data.Read` scope.
   * The client app uses MSAL to get an access token with `scp=Data.Read`.

2. **Microsoft Entra ID**

   * Authenticates the user.
   * Issues an access token with:

     * `aud` set to my custom API audience.
     * `scp` containing `Data.Read`.

3. **Protected Flask API**

   * Receives a request to `/data` with `Authorization: Bearer <token>`.
   * Validates the token using:

     * JWKS endpoint
     * Issuer
     * Audience
     * Scopes
   * Returns a JSON payload only if all checks pass.

Quick decision guide:

* Am I calling Microsoft Graph?

  * Yes → use Graph audience and Graph permissions.
  * No → define a custom API audience and custom scopes, like in this lab.

---

## 🗂 Repository Structure

This lab lives under the IAM Protocols repo as:

`Lab 4 – Protect a Custom API with JWT Bearer Tokens (Resource + Client)/`

```text
Lab 4 – Protect a Custom API with JWT Bearer Tokens (Resource + Client)/
├── api/
│   ├── app.py              # Flask API protected by JWT bearer validation
│   ├── .env                # TENANT_ID, API_AUDIENCE, JWKS_URL (local only)
│   └── requirements.txt    # Flask, PyJWT, python-dotenv, requests
├── client/
│   ├── client_delegated.py # MSAL client that requests Data.Read and calls /data
│   └── .env                # TENANT_ID, CLIENT_ID, CLIENT_SECRET, SCOPE
├── .venv/                  # Virtual environment (ignored by Git)
├── .gitignore
└── screenshots/
    ├── 01-protected-api-overview.png
    ├── 02-expose-an-api-scope.png
    ├── 03-data-read-scope-details.png
    ├── 04-client-app-api-permissions.png
    ├── 05-grant-admin-consent-lab4.png
    ├── 06-terminal-access-token-acquired.png
    ├── 07-terminal-status-200-from-api.png
    └── 08-curl-401-missing-authorization.png
```

---

## 🔒 Safety and Secrets

For this lab I keep secrets out of GitHub:

* `api/.env` and `client/.env` are **local only** and listed in `.gitignore`.

`api/.env` contains values like:

```ini
TENANT_ID=xxxxxxxxxxxxxxxxx
API_AUDIENCE=api://xxxxxxxxxxxxxxx
JWKS_URL=https://login.microsoftonline.com/xxxxxxxxxxxxxxxxxxx/discovery/v2.0/keys
```

`client/.env` contains values like:

```ini
TENANT_ID=<Directory (tenant) ID>
CLIENT_ID=<Lab4-ClientApp client ID>
CLIENT_SECRET=<client secret VALUE>
SCOPE=api://xxxxxxxxxxxxxxxxxxxxx/Data.Read
```

Both apps load these with `python-dotenv`:

```python
from dotenv import load_dotenv
load_dotenv()
```

In a production setting, these values would live in a secret manager like Azure Key Vault or be replaced by managed identities or certificates.

---

## 📋 Step 1 – App Registration: Protected API

1. Go to Entra admin center: `https://entra.microsoft.com`.
2. Navigate to: Identity → Applications → App registrations → New registration.
3. Create the API app:

   * Name: `iam-protocols-lab4-protected-api`
   * Supported account types: Single tenant.
   * Redirect URI: leave empty for this lab.
4. Click **Register**.
5. On the Overview page, capture:

   * Application (client) ID → used in `API_AUDIENCE`.
   * Directory (tenant) ID → `TENANT_ID`.

---

## 📋 Step 2 – Expose API and Custom Scope

1. In the Lab4-ProtectedApi app, go to **Expose an API**.
2. If there is no Application ID URI, set one:

   * `api://<Application (client) ID>`
3. Under **Scopes defined by this API**, click **Add a scope**:

   * Scope name: `Data.Read`
   * Who can consent: `Admins and users`
   * Admin consent display name: `Read data from Lab 4 API`
   * Admin consent description: `Allows the application to read protected data from the Lab 4 API.`
   * User consent display name: `Read data from Lab 4 API`
   * User consent description: `Allows the app to read protected data from the Lab 4 API.`
   * State: Enabled
4. Save the scope.
5. Note the full scope URI that is shown:

   * `api://fd6b803e-3e2e-4294-aadc-39885e0b3197/Data.Read`

This becomes the `SCOPE` for the client app.

---

## 📋 Step 3 – App Registration: Client Application

1. In Entra, create a second app registration:

   * Name: `iam-protocols-lab4-client`
   * Supported account types: Single tenant.
2. On the Overview page, capture:

   * Application (client) ID → `CLIENT_ID`.
3. Go to **Certificates & secrets**:

   * Create a client secret for the lab.
   * Copy the secret value → `CLIENT_SECRET`.
4. Go to **API permissions** → **Add a permission**:

   * Choose **My APIs**.
   * Select `Lab4-ProtectedApi`.
   * Choose **Delegated permissions**.
   * Check `Data.Read`.
   * Click **Add permissions**.
5. Click **Grant admin consent** for the tenant and confirm.

---

## 📋 Step 4 – Local Setup

### 4.1 Virtual environment and dependencies

From the Lab 4 root folder:

```bash
cd "Lab 4 – Protect a Custom API with JWT Bearer Tokens (Resource + Client)"

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install flask python-dotenv requests pyjwt cryptography msal
pip freeze > api/requirements.txt
```

### 4.2 Environment files

`api/.env`:

```ini
TENANT_ID=<Directory (tenant) ID>
API_AUDIENCE=api://<Lab4-ProtectedApi client ID>
JWKS_URL=https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys
```

`client/.env`:

```ini
TENANT_ID=<Directory (tenant) ID>
CLIENT_ID=<Lab4-ClientApp client ID>
CLIENT_SECRET=<client secret VALUE>
SCOPE=api://<Lab4-ProtectedApi client ID>/Data.Read
```

Ensure `.env` files are listed in `.gitignore`.

---

## 📋 Step 5 – Implementation

### 5.1 Flask protected API (`api/app.py`)

Core pieces:

```python
import os
from functools import wraps

from flask import Flask, jsonify, request, g
from dotenv import load_dotenv
import jwt
from jwt import PyJWKClient, InvalidTokenError

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
API_AUDIENCE = os.getenv("API_AUDIENCE")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
ISSUER = f"{AUTHORITY}/v2.0"
JWKS_URL = os.getenv("JWKS_URL")

jwks_client = PyJWKClient(JWKS_URL)

app = Flask(__name__)


def validate_jwt(token, required_scopes=None):
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=ISSUER,
        )
    except InvalidTokenError as ex:
        return None, ("invalid_token", str(ex))

    scopes_claim = claims.get("scp", "")
    scope_list = scopes_claim.split() if isinstance(scopes_claim, str) else []

    required_scopes = required_scopes or []
    missing = [s for s in required_scopes if s not in scope_list]
    if missing:
        return None, ("insufficient_scope", f"Missing scopes: {', '.join(missing)}")

    return claims, None


def require_auth(required_scopes=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            parts = auth_header.split()

            if len(parts) != 2 or parts[0].lower() != "bearer":
                return (
                    "",
                    401,
                    {
                        "WWW-Authenticate": (
                            'Bearer error="invalid_token", '
                            'error_description="Missing or malformed Authorization header"'
                        )
                    },
                )

            token = parts[1]
            claims, error = validate_jwt(token, required_scopes=required_scopes)

            if error:
                code, desc = error
                status = 403 if code == "insufficient_scope" else 401
                return (
                    "",
                    status,
                    {
                        "WWW-Authenticate": (
                            f'Bearer error="{code}", error_description="{desc}"'
                        )
                    },
                )

            g.user_claims = claims
            return f(*args, **kwargs)

        return wrapper

    return decorator


@app.route("/data")
@require_auth(required_scopes=["Data.Read"])
def get_data():
    return jsonify({"message": "Protected data from Lab 4 API", "claims": g.user_claims})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

### 5.2 Client script (`client/client_delegated.py`)

```python
import os
import requests
from dotenv import load_dotenv
import msal

load_dotenv()

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
SCOPE = [os.environ["SCOPE"]]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
API_URL = "http://localhost:5000/data"


def acquire_token():
    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
    )

    result = None

    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPE, account=accounts[0])

    if not result:
        flow = app.initiate_device_flow(scopes=SCOPE)
        if "user_code" not in flow:
            raise SystemExit(f"Failed to create device flow: {flow}")

        print("Requesting token for scope:", SCOPE[0])
        print("To sign in, use a browser to open the page:")
        print(flow["verification_uri"])
        print("and enter the code:")
        print(flow["user_code"])

        result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        raise SystemExit(f"Failed to acquire token: {result}")

    return result


def call_api(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(API_URL, headers=headers)
    print("Status:", r.status_code)
    print("Raw response:", r.text)


if __name__ == "__main__":
    result = acquire_token()
    print("Access token acquired.\n")
    call_api(result["access_token"])
```

---

## 📋 Step 6 – Testing

With the virtual environment active:

Terminal 1 (API):

```bash
cd "Lab 4 – Protect a Custom API with JWT Bearer Tokens (Resource + Client)/api"
source ../.venv/bin/activate
python app.py
```

Terminal 2 (client):

```bash
cd "Lab 4 – Protect a Custom API with JWT Bearer Tokens (Resource + Client)/client"
source ../.venv/bin/activate
python client_delegated.py
```

Expected behavior:

* Device code flow prompts with a URL and code.
* After signing in and consenting, the client prints:

  * `Access token acquired.`
  * `Status: 200`
  * JSON response from the API.

Extra check with `curl` (no token):

```bash
curl -i http://localhost:5000/data
```

Expected:

* `HTTP/1.1 401 UNAUTHORIZED`
* `WWW-Authenticate: Bearer error="invalid_token", error_description="Missing or malformed Authorization header"`

---

## 📷 Screenshots

| # | Screenshot | Description |
|---:|---|---|
| 1 | ![01-protected-api-overview](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/01-protected-api-overview.png) | App registration overview for **Lab4-ProtectedApi** showing Application (client) ID and Directory (tenant) ID. |
| 2 | ![02-expose-an-api-scope](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/02-expose-an-api-scope.png) | **Expose an API** blade showing the Application ID URI and the **Data.Read** scope being defined for the protected API. |
| 3 | ![03-data-read-scope-details](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/03-data-read-scope-details.png) | **Add a scope** pane showing the **Data.Read** consent display names/descriptions and scope state set to Enabled. |
| 4 | ![04-client-app-api-permissions](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/04-client-app-api-permissions.png) | Client app **API permissions** flow selecting **Delegated permissions** for the Lab4-ProtectedApi resource. |
| 5 | ![05-grant-admin-consent-lab4](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/05-grant-admin-consent-lab4.png) | Client app permissions page showing **Data.Read** with status **Granted** after consent was granted. |
| 6 | ![06-terminal-access-token-acquired](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/06-terminal-access-token-acquired.png) | Terminal output showing the client successfully acquiring an access token and calling the API endpoint. |
| 7 | ![07-terminal-status-200-from-api](https://github.com/miadco/IAM-Protocols/blob/main/Lab%204%3A%20Protect%20a%20Custom%20API%20with%20JWT%20Bearer%20Tokens%20(Resource%20%2B%20Client)/Screenshots/07-terminal-status-200-from-api.png) | Terminal output confirming the protected API returned **Status: 200** for `/data` with a valid token and scope. |

---

## 🧯 Errors and Troubleshooting

### 1. PyJWKClientConnectionError – HTTP Error 400: Bad Request

**What I saw**

* API returned `Status: 500`.
* Flask debugger showed:

  `jwt.exceptions.PyJWKClientConnectionError: Fail to fetch data from the url, err: "HTTP Error 400: Bad Request"`

**Root cause**

* The JWKS URL in `JWKS_URL` was incorrect.

**Fix**

* Set `JWKS_URL` to:

  `https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys`

* Restarted the API server. The error disappeared.

**Lesson**

* JWKS URLs must match Entra’s discovery endpoint exactly. A typo or wrong path results in 400s when fetching keys.

---

### 2. 401 Unauthorized – Missing or Malformed Authorization Header

**What I saw**

* Running `curl -i http://localhost:5000/data` returned:

  * `HTTP/1.1 401 UNAUTHORIZED`
  * `WWW-Authenticate: Bearer error="invalid_token", error_description="Missing or malformed Authorization header"`

**Root cause**

* This was expected. Curl was not sending any bearer token.

**Lesson**

* The API correctly distinguishes between “no token” (401) and “valid token but insufficient scope” (403).

---

### 3. Port 5000 Already in Use

**What I saw**

* Running `python app.py` sometimes produced:

  `Port 5000 is in use by another program.`

**Root cause**

* Another Flask instance was still running, or a previous session did not exit cleanly.

**Fix**

* Stopped the old process (Ctrl+C, or kill by PID).
* Restarted the API server.

---

## 💡 What I Learned

From this lab I can now say:

* I know how to turn a **plain Flask app** into a **proper OAuth 2.0 resource server**.
* I understand how to:

  * Expose a custom API in Entra.
  * Define scopes.
  * Configure a client app to request those scopes.
* I can read and debug JWT validation problems:

  * Wrong JWKS URL.
  * Wrong audience.
  * Missing or malformed Authorization header.
* I understand what the API should send back:

  * `401` for missing or invalid tokens.
  * `403` for valid tokens that lack the required scope.
* I have a concrete example of a **custom microservice** that trusts Microsoft Entra as its identity provider and enforces access via JWT bearer tokens.

---

## 💼 Business Relevance

This lab maps directly to real-world identity scenarios:

* Internal line-of-business APIs that must be protected with Entra ID.
* Microservices that accept tokens issued by a central identity provider.
* Architectures where Graph is not the only resource. Teams often build their own APIs behind APIM or behind a gateway.

Being able to design and debug this pattern means I can:

* Help teams securely expose internal APIs to front-end apps, services, or partners.
* Review whether a custom API is validating tokens correctly (issuer, audience, scopes).
* Propose improvements like:

  * Returning proper WWW-Authenticate headers.
  * Logging JWT validation failures for security investigations.

---

## 🎤 Interview Talking Points

Some ways I can describe this lab in an interview:

* “I built a custom Flask API and turned it into an OAuth 2.0 protected resource that validates JWT bearer tokens issued by Microsoft Entra ID.”
* “I exposed a custom scope called Data.Read, wired a client app to request that scope, and enforced it in the API using the scp claim.”
* “I fixed a PyJWKClientConnectionError by identifying that the JWKS URL was wrong and updating it to the correct Entra discovery endpoint.”
* “I validated that the API returns 401 when the Authorization header is missing and 200 when a valid token with Data.Read is present.”
* “This lab shows I can move beyond Microsoft Graph and protect first-party APIs with the same identity platform.”

---

## 🙏 Acknowledgments

This lab was built using AI-assisted development as a learning accelerator.

AI helped with:

* Structuring the lab and README.
* Drafting the Flask + JWT + MSAL patterns.
* Interpreting JWT and JWKS errors and mapping them back to Entra configuration.

I own:

* The configuration and troubleshooting in my tenant.
* The working protected API and client.
* The understanding of how custom scopes, JWT validation, and bearer tokens apply to real IAM and microservice architectures.

Together with Labs 1–3, this lab completes the story:

* **Lab 1**: Authenticate a user with OIDC.
* **Lab 2**: Call Microsoft Graph on behalf of that user with delegated permissions.
* **Lab 3**: Call Microsoft Graph as an app-only daemon with application permissions.
* **Lab 4**: Protect my own API with JWT bearer tokens issued by Entra ID.
