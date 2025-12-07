## IAM Protocols – Lab 3: Daemon App with OAuth 2.0 Client Credentials (App-Only Access)  


## Learning Objectives

By the end of this lab, I will be able to:

- ✓ Distinguish between **delegated** and **application** permissions.
- ✓ Implement the **OAuth 2.0 client credentials** flow in Python.
- ✓ Grant and verify **admin consent** for Microsoft Graph in Entra.
- ✓ Apply **least-privilege** principles to app registrations.
- ✓ Troubleshoot common Microsoft Graph **permission errors**.
- ✓ Inspect and interpret **app-only access tokens** (roles vs scp, audience, lifetime).

---

📌 Overview

In Lab 1, I focused on authentication: using OpenID Connect (OIDC) and the authorization code flow to get an ID token and prove who the user is.

In Lab 2, I moved into authorization with delegated permissions:

- I used the OAuth 2.0 authorization code flow to obtain an access token for Microsoft Graph.
- I called the `/v1.0/me` endpoint on behalf of the signed-in user.

In **Lab 3**, I extend this to **application permissions** and background jobs:

- I use the **OAuth 2.0 client credentials flow** from a headless Python script.
- The app authenticates **as itself** using `client_id` and `client_secret`.
- It obtains an **app-only access token** and calls Microsoft Graph:
  - `/v1.0/users` with `User.Read.All`
  - `/v1.0/auditLogs/signIns` with `AuditLog.Read.All`
- There is no browser and no interactive sign-in. This is the pattern used by scheduled reports, monitoring tools, and security daemons.

The point of this lab is to prove that I understand how:

- A **confidential client** app is registered in Microsoft Entra ID for app-only use.
- It is granted **application permissions** for Microsoft Graph.
- It performs the **client credentials flow** and uses the access token to call Graph without any user context.

---

🎯 Objectives

By the end of this lab I have:

- Registered a daemon-style confidential client app in Microsoft Entra ID for Lab 3.
- Created a client secret that the Python script uses to authenticate.
- Added **application** permissions:
  - `User.Read.All`
  - `AuditLog.Read.All`
- Implemented a Python script using `msal` to:
  - Request an app-only token via `acquire_token_for_client`.
  - Call `https://graph.microsoft.com/v1.0/users`.
  - Call `https://graph.microsoft.com/v1.0/auditLogs/signIns`.
- Handled a `403 Authorization_RequestDenied` error and fixed it by granting admin consent.
- Explained the difference between:
  - Delegated vs application permissions.
  - User-driven flows vs daemon-style flows.
- Inspected the access token to see which **claims** (roles vs scp) are actually present.

---

🧠 Key Concepts

**OAuth 2.0 Client Credentials Flow**  
A non-interactive flow where a trusted app authenticates with **client ID + secret or certificate** and receives an app-only access token. Used for daemons, services, and background jobs.

**Application Permissions (Microsoft Graph)**  
Permissions granted directly to an app (for example, `User.Read.All`, `AuditLog.Read.All`). The app acts as itself and is not limited by any one user’s role. These require admin consent.

**Delegated vs Application Permissions**

- Delegated: app acts **on behalf of** a signed-in user; token has `scp` claim.
- Application: app acts **as itself**; token has `roles` claim and no user.

**Confidential Client Application (Daemon)**  
A server-side or background app that can safely hold a secret and perform backchannel token requests. There is no interactive sign-in or redirect URI for this lab.

**Microsoft Graph Users and Audit Logs**

- `/v1.0/users`: returns directory user objects.
- `/v1.0/auditLogs/signIns`: returns sign-in events useful for security and monitoring.

**Admin Consent**  
Even if an app lists an application permission, it cannot use it until an admin grants consent. Missing admin consent surfaces as `Authorization_RequestDenied` from Graph.

---

### Understanding Your Token

Before calling Graph, I can inspect my token at `https://jwt.ms` to verify what I actually got from Entra:

- **roles**  
  - Contains the application permissions granted to the app (for example, `"User.Read.All"`, `"AuditLog.Read.All"`).
- **scp**  
  - For app-only tokens from client credentials, this is typically **absent**.  
  - Its presence usually indicates a **delegated** flow instead.
- **aud** (audience)  
  - Should match `https://graph.microsoft.com` for Microsoft Graph calls.
- **appid**  
  - The client ID of the application.
- **exp / nbf**  
  - Token validity window (usually about 1 hour).

If `roles` is empty or missing my expected permissions, Graph will not authorize the call even if authentication succeeded.

---

### Token Lifecycle (Client Credentials)

For this lab:

- Access tokens are short-lived (commonly around **1 hour**).
- Client credentials flow **does not use refresh tokens**.
- When the token expires, the daemon simply calls `acquire_token_for_client` again to get a new one.
- In longer-running processes, I should:
  - Cache the token in memory.
  - Reuse it until it expires.
  - Only request a new token when needed.

This keeps performance reasonable and avoids hammering the token endpoint.

---

🧠 Mental Model

I treat this lab as a three-step conversation between the daemon, Microsoft Entra ID, and Microsoft Graph.

1. **Daemon app authenticates as itself**

   The Python script calls Entra ID:

   - POST to `/{tenant}/oauth2/v2.0/token`
   - Sends `client_id`, `client_secret`, and `scope=https://graph.microsoft.com/.default`.

   Entra ID returns an **app-only access token** representing the application.

2. **Graph authorizes based on application permissions**

   The script calls:

   - `GET https://graph.microsoft.com/v1.0/users` or  
   - `GET https://graph.microsoft.com/v1.0/auditLogs/signIns`

   with `Authorization: Bearer <access_token>`.

   Graph checks which **application permissions** are in the token (for example, `User.Read.All`, `AuditLog.Read.All`) via the `roles` claim.

3. **Daemon processes results**

   - For `/users`, the script lists user IDs and user principal names.
   - For `/auditLogs/signIns`, the script lists sign-in event IDs and UPNs.

**Success condition:**  

- I run `python3 app.py` with no UI and no browser.
- I see `Access token acquired.`.
- I see user data and sign-in data printed from live Microsoft Graph, and I can explain which permissions allowed each call.

---

### Quick Flow Decision

```text
Is there a user interacting with the app?
├─ Yes → Use delegated permissions → Labs 1–2 patterns
└─ No  → Use application permissions → Lab 3 pattern (client credentials)
````

---

🗂 Repository Structure

This lab lives under the IAM Protocols repo as:

```text
Lab 3 – Daemon App with OAuth 2.0 Client Credentials/
├── app.py                    # Python daemon using client credentials and Microsoft Graph
├── .env                      # TENANT_ID, CLIENT_ID, CLIENT_SECRET, GRAPH_SCOPE (local only)
├── requirements.txt          # msal, python-dotenv, requests
└── screenshots/
    ├── 01-register-daemon-app.png
    ├── 02-app-overview-ids.png
    ├── 03-create-client-secret.png
    ├── 04-api-permissions-user-read-all.png
    ├── 05-api-permissions-auditlog-read-all.png
    ├── 06-daemon-users-output.png
    └── 07-daemon-signins-output.png
```

---

🔒 Safety and Secrets

For this lab I keep secrets out of GitHub:

* `.env` is local only and is added to `.gitignore`.

* `.env` contains values like:

  ```env
  TENANT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
  CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  CLIENT_SECRET=your-real-client-secret-value
  GRAPH_SCOPE=https://graph.microsoft.com/.default
  ```

* `app.py` reads these via `python-dotenv`:

  ```python
  from dotenv import load_dotenv
  load_dotenv()

  TENANT_ID = os.environ["TENANT_ID"]
  CLIENT_ID = os.environ["CLIENT_ID"]
  CLIENT_SECRET = os.environ["CLIENT_SECRET"]
  SCOPE = [os.environ.get("GRAPH_SCOPE", "https://graph.microsoft.com/.default")]
  ```

I only commit safe code and configuration patterns. The actual secret and environment values live only on my machine and in the Entra portal.

In a production setting, these values would be stored in a secret manager like Azure Key Vault, replaced by certificates, or replaced by managed identities to avoid shared secrets entirely.

---

📋 Step 1 – App Registration in Microsoft Entra ID

1. Go to Entra admin center: `https://entra.microsoft.com`.

2. Navigate to: **Identity → Applications → App registrations → New registration**.

3. Fill in:

   * **Name:** `iam-protocols-lab3-daemon-client-credentials`
   * **Supported account types:** Accounts in this organizational directory only (Single tenant).
   * **Redirect URI:** leave empty (no browser-based flow).

4. Click **Register**.

On the Overview page, capture:

* **Application (client) ID → CLIENT_ID**
* **Directory (tenant) ID → TENANT_ID**

---

📋 Step 2 – Client Secret and API Permissions

**2.1 Create a client secret**

1. Go to **Certificates & secrets → Client secrets**.
2. Click **New client secret**.
3. Description: `lab3-daemon-secret`.
4. Choose an expiry (default is fine for the lab).
5. Click **Add**.
6. Immediately copy the **Value** (not the ID) → `CLIENT_SECRET`.

**2.2 Configure application permissions**

1. Go to **API permissions → Add a permission**.

2. Choose **Microsoft Graph**.

3. Select **Application permissions**.

4. Add:

   * `User.Read.All`
   * `AuditLog.Read.All`

5. Click **Add permissions**.

**2.3 Grant admin consent**

1. On the **API permissions** blade, click **Grant admin consent for <tenant>**.
2. Confirm with **Yes**.
3. Verify that the **Status** for both permissions shows **Granted for <tenant>**.

---

📋 Step 3 – Local Setup

All commands are from the Lab 3 folder on my Linux machine.

**3.1 Virtual environment and dependencies**

```bash
cd "Lab 3 – Daemon App with OAuth 2.0 Client Credentials"

python3 -m venv .venv
source .venv/bin/activate

python3 --version
which python3
```

Install dependencies:

```bash
pip install --upgrade pip
pip install msal python-dotenv requests
pip freeze > requirements.txt
```

**3.2 Environment**

Create `.env` in the lab folder with:

```env
TENANT_ID=<Directory (tenant) ID>
CLIENT_ID=<Application (client) ID>
CLIENT_SECRET=<client secret VALUE>
GRAPH_SCOPE=https://graph.microsoft.com/.default
```

Ensure `.env` is listed in `.gitignore`.

---

📋 Step 4 – Implementation

**4.1 Daemon implementation (users)**

`app.py`:

```python
import os
import requests
from dotenv import load_dotenv
import msal

load_dotenv()

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
SCOPE = [os.environ.get("GRAPH_SCOPE", "https://graph.microsoft.com/.default")]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0/users?$top=10"


def get_app_only_token():
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )

    result = app.acquire_token_for_client(scopes=SCOPE)

    if "access_token" not in result:
        raise SystemExit(f"Failed to acquire token: {result}")

    return result["access_token"]


def call_graph(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(GRAPH_ENDPOINT, headers=headers)

    if response.status_code != 200:
        raise SystemExit(
            f"Graph call failed: {response.status_code} {response.text}"
        )

    return response.json()


def main():
    print("=== Lab 3 – Daemon App (Client Credentials) ===")
    token = get_app_only_token()
    print("Access token acquired.")

    data = call_graph(token)
    print("Graph response (first few users):")
    for user in data.get("value", []):
        print(user.get("id"), "|", user.get("userPrincipalName"))


if __name__ == "__main__":
    main()
```

**4.2 Upgrade to sign-in logs**

Once `/users` works, I switch to sign-ins by changing:

```python
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=10"
```

and updating `main()`:

```python
def main():
    print("=== Lab 3 – Daemon App (Client Credentials) ===")
    token = get_app_only_token()
    print("Access token acquired.")

    data = call_graph(token)
    print("Graph response (first few sign-ins):")
    for event in data.get("value", []):
        print(event.get("id"), "|", event.get("userPrincipalName"))
```

---

📋 Step 5 – Testing

With the virtual environment active:

```bash
python3 app.py
```

First run:

* If admin consent is missing, Graph returns:

  ```text
  Authorization_RequestDenied: Insufficient privileges to complete the operation.
  ```

* After granting admin consent for `User.Read.All` and `AuditLog.Read.All`:

  * I see `Access token acquired.`
  * I then see either a list of users or a list of sign-in events, depending on the endpoint.

Optional checkpoint:

* Copy the access token from the script output (temporarily), paste it into `https://jwt.ms`, and verify:

  * `aud` is `https://graph.microsoft.com`.
  * `roles` contains `User.Read.All` and/or `AuditLog.Read.All`.
  * There is no `scp` claim (confirming app-only).

---

📈 Outcomes

After finishing this lab I can:

* Demonstrate a working OAuth 2.0 **client credentials** flow from Python to Microsoft Entra ID.
* Explain how an app requests **application permissions** for Microsoft Graph and why they require admin consent.
* Show a real example of using an app-only access token to call:

  * `/v1.0/users` for directory inventory.
  * `/v1.0/auditLogs/signIns` for security monitoring.
* Talk through how permission mismatches and missing admin consent surface as `Authorization_RequestDenied` errors.
* Describe the security impact if a daemon app’s client secret leaks and how to reduce that risk.
* Inspect an access token and confirm whether it represents:

  * A user (delegated) or
  * An application (app-only).

---

📷 Screenshots

| #  | Screenshot                                                                 | Description                                                                                                      |
|----|----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| 1  | ![01-app-overview-ids](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/01-app-overview-ids.png?raw=1) | App registration overview blade showing the Lab 3 daemon app with Application (client) ID and Directory ID.     |
| 2  | ![02-create-client-secret](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/02-create-client-secret.png?raw=1) | Certificates & secrets blade with the “Add a client secret” dialog for `lab3-daemon-secret`.                    |
| 3  | ![03-choose-application-permissions](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/03-choose-application-permissions.png?raw=1) | Request API permissions pane for Microsoft Graph highlighting **Application permissions** for daemons.          |
| 4  | ![04-permission-details-user-read-all](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/04-permission-details-user-read-all.png?raw=1) | Permission details pane for `User.Read.All` showing it as an application permission that requires admin consent. |
| 5  | ![05-grant-admin-consent](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/05-grant-admin-consent.png?raw=1) | Grant admin consent confirmation dialog for the Lab 3 daemon app.                                               |
| 6  | ![06-403-authorization-requestdenied](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/06-403-authorization-requestdenied.png?raw=1) | Terminal output from `python3 app.py` showing the 403 `Authorization_RequestDenied` error from Microsoft Graph. |
| 7  | ![07-api-permissions-granted](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/07-api-permissions-granted.png?raw=1) | API permissions blade showing `User.Read.All` application permission with status “Granted for Cumulus Labs”.    |
| 8  | ![08-add-auditlog-read-all-permission](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/08-add-auditlog-read-all-permission.png?raw=1) | Request API permissions pane with `AuditLog.Read.All` selected before adding it to the app.                     |
| 9  | ![09-daemon-app-code-snippet](https://github.com/miadco/IAM-Protocols/blob/main/Lab%203%3A%20Daemon%20App%20with%20OAuth%202.0%20Client%20Credentials%20(App-Only%20Access)/screenshots/09-daemon-app-code-snippet.png?raw=1) | Nano editor view of `app.py` showing environment variable loading and the client credentials flow code.         |


---

🧯 Errors and Troubleshooting

**1. Graph 403 – Authorization_RequestDenied**

*What I saw*

After the token was acquired, the script failed with:

```text
Graph call failed: 403 {"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."...}}
```

*Root cause*

The app had `User.Read.All` and/or `AuditLog.Read.All` configured, but **admin consent** had not been granted. Graph rejected the call because the permissions were not active for the application.

*What I did*

* Went to **API permissions** for the Lab 3 app.
* Clicked **Grant admin consent for <tenant>**.
* Verified that the Status column showed **Granted for <tenant>** for both application permissions.
* Reran `python3 app.py`. The 403 error disappeared and Graph returned data.

*Lesson*

A valid token is not enough. For application permissions, **admin consent** is required before Graph will honor them.

---

### Common Pitfalls

* Using **delegated permissions** in a daemon app and wondering why it cannot run without a user.
* Forgetting to click **Grant admin consent**, leading to 403s even though the permission appears in the portal.
* Using the wrong `TENANT_ID` in the `AUTHORITY` URL and getting `invalid_client` or tenant errors.
* Assuming client credentials will return **refresh tokens**; it does not. Access tokens must be reacquired.

---

💡 What I Learned

From this lab I can now say:

* I understand how the **client credentials flow** works end-to-end:

  * The daemon app authenticates with client ID and secret.
  * Entra returns an app-only access token.
  * Graph uses application permissions in that token to authorize requests via the `roles` claim.

* I can clearly distinguish between:

  * Delegated permissions (user in the loop, `scp` claim).
  * Application permissions (no user, `roles` claim).

* I know how to read and fix `Authorization_RequestDenied` errors by checking:

  * Whether the right permission is assigned.
  * Whether admin consent has been granted.
  * Whether the token actually contains the expected roles.

* I have a concrete example of a **security daemon** that:

  * Reads users.
  * Reads sign-in logs.

* I reinforced good habits around:

  * Using `.env` and `.gitignore` to keep secrets local.
  * Thinking about the **blast radius** of app-only permissions and leaked client secrets.

---

💼 Business Relevance

This lab maps directly to how real organizations automate Microsoft 365 and Entra:

* Scheduled jobs that export users, groups, and admins for governance reviews.
* Security monitoring tools that pull sign-in logs into SIEM or data lakes.
* Compliance and audit scripts that need tenant-wide read access.

Being able to build and debug this pattern means I can:

* Discuss how internal tools authenticate against Entra ID without user interaction.
* Evaluate whether a given service principal is over-permissioned.
* Propose more secure designs, such as:

  * Using certificates instead of shared secrets.
  * Narrowing application permissions to only what is required.

---

🎤 Interview Talking Points

Some ways I can describe this lab in an interview:

* “I built a Python daemon that uses the OAuth 2.0 client credentials flow with Microsoft Entra ID to obtain an app-only access token and call Microsoft Graph.”
* “The app is registered as a confidential client with application permissions like `User.Read.All` and `AuditLog.Read.All`, and it runs without any user interaction.”
* “I saw a `403 Authorization_RequestDenied` error at first. I traced it back to missing admin consent for the app’s Graph permissions, granted consent in the Entra portal, and confirmed that the daemon could successfully read users and sign-in logs.”
* “I understand the risk of over-permissioned service principals. In a production setting, I would move the secret into Key Vault, use certificate-based auth, and restrict permissions to the minimum required to support the automation.”
* “I validated the access token at jwt.ms, checked the `roles` claim to confirm app-only permissions, and used that as a sanity check whenever Graph returned a 403.”

---

🙏 Acknowledgments

This lab was built using AI-assisted development as a learning accelerator.

AI helped with:

* Structuring the lab and README.
* Drafting the Python + MSAL patterns.
* Interpreting Graph errors and mapping them back to Entra configuration.

I own:

* The configuration and troubleshooting in my tenant.
* The working daemon app and Graph calls.
* The understanding of how client credentials, application permissions, and admin consent map to real IAM and Microsoft 365 automation scenarios.

This lab sits on top of Labs 1 and 2 and completes the picture:

* Lab 1: “Who are you?” (ID token, authentication).
* Lab 2: “What can this app do on your behalf?” (delegated access token + scopes).
* **Lab 3:** “What can this app do on its own?” (app-only access token + application permissions).
