
# IAM Protocols – Lab 2: Call Microsoft Graph with OAuth 2.0 Authorization Code Flow

**Estimated Time:** 2–4 hours  

---

## 📌 Overview

In **Lab 1**, I focused on **authentication**: using OpenID Connect (OIDC) and the authorization code flow to get an **ID token** and prove who the user is.

In **Lab 2**, I move into **authorization**:

- I use the **OAuth 2.0 authorization code flow** to obtain an **access token** for Microsoft Graph.  
- I call the `/v1.0/me` endpoint on behalf of the signed-in user.  
- I render the user’s **display name**, **user principal name**, and **object ID** returned directly from Graph.

The UI is intentionally simple. The point of this lab is to prove that I understand how:

1. A real web app is registered in **Microsoft Entra ID**.  
2. It requests **delegated permissions** like `User.Read`.  
3. It performs the **auth code flow** and uses the access token to call **Microsoft Graph**.

---

## 🎯 Objectives

By the end of this lab I have:

- Registered a **confidential client** app in Microsoft Entra ID for Lab 2.  
- Configured a **web redirect URI** for `http://localhost:5000/getAToken`.  
- Created a **client secret** for the Flask app to use in the token exchange.  
- Added a **delegated Microsoft Graph permission**: `User.Read`.  
- Implemented `/login`, `/getAToken`, `/graph_me`, and `/logout` using **MSAL for Python**.  
- Successfully called `https://graph.microsoft.com/v1.0/me` and displayed my profile information.

---

## 🧠 Key Concepts

- **OAuth 2.0 Authorization Code Flow**  
  Browser-based flow where the app redirects the user to Entra, receives an authorization code, and exchanges that code for tokens on the backend.

- **ID Token vs Access Token**  
  - **ID token**: proves who the user is (authentication).  
  - **Access token**: proves what the app can do on the user’s behalf (authorization).

- **Delegated Permissions (Microsoft Graph)**  
  Permissions like `User.Read` that allow the app to act as the signed-in user.

- **Confidential Client Application**  
  A server-side app that can safely hold a **client secret** and perform backchannel token exchanges.

- **Microsoft Graph `/me`**  
  Endpoint that returns data about the signed-in user – display name, UPN, ID, etc.

- **Redirect URI Matching**  
  The **redirect URI in the app registration must exactly match** the one used by the app. Any mismatch causes `AADSTS50011` errors.

---

## 🧠 Mental Model

I treat this lab as a **four-step conversation** between my Flask app, Microsoft Entra ID, and Microsoft Graph:

1. **My app starts the flow**  
   `/login` uses MSAL to build an authorization request URL (with `client_id`, `scope`, `redirect_uri`) and redirects the browser to Entra.

2. **Entra handles identity + consent**  
   Microsoft Entra ID shows the sign-in and consent screen for `User.Read`. After I sign in and accept, Entra redirects back to `/getAToken` with an **authorization code**.

3. **My app proves it is trusted**  
   `/getAToken` uses the **client secret** to exchange the code for an ID token + access token. The user claims and the access token are stored in the Flask session.

4. **My app calls Graph on my behalf**  
   `/graph_me` sends `Authorization: Bearer <access_token>` to `https://graph.microsoft.com/v1.0/me` and renders the returned profile data in the browser.

**Success condition:**  
I click “Sign in and call Microsoft Graph”, sign in, consent, and then see my **display name**, **UPN**, and **ID** coming back from the live Graph `/me` endpoint.

---

## 🗂 Repository Structure

This lab lives under the IAM Protocols repo as:

```text
Lab 2 - Call Microsoft Graph with OAuth2/
├── app.py                    # Flask app, MSAL auth code flow, Graph /me call
├── config.py                 # Reads environment variables from .env (local only)
├── .env                      # CLIENT_ID, TENANT_ID, CLIENT_SECRET (local only)
├── requirements.txt          # Flask, msal, python-dotenv, requests
├── templates/
│   ├── index.html            # Landing page with “Sign in and call Microsoft Graph”
│   ├── graph_me.html         # Displays /me result (name, UPN, ID)
│   └── error.html            # Shows auth / Graph errors as JSON
└── screenshots/
    ├── 01-create-client-secret.png
    ├── 02-request-api-permissions.png
    ├── 03-api-permissions-user-read.png
    ├── 04-authentication-redirect-uris.png
    ├── 05-edit-redirect-uri.png
    ├── 06-local-lab2-home.png
    ├── 07-microsoft-consent-screen.png
    ├── 08-graph-me-result.png
    └── 09-redirect-uri-mismatch-error.png      # Used in troubleshooting section
````

---

## 🔒 Safety & Secrets

For this lab I keep secrets **out of GitHub**:

* `.env` and `config.py` are **local-only** and should be added to `.gitignore`.

* `.env` contains:

  ```env
  CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  CLIENT_SECRET=your-real-client-secret-value
  TENANT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
  FLASK_SECRET_KEY=dev-change-me
  ```

* `config.py` loads these values via `python-dotenv`:

  ```python
  import os
  from dotenv import load_dotenv

  load_dotenv()

  CLIENT_ID = os.getenv("CLIENT_ID")
  CLIENT_SECRET = os.getenv("CLIENT_SECRET")
  TENANT_ID = os.getenv("TENANT_ID")

  AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
  REDIRECT_PATH = "/getAToken"
  SCOPE = ["User.Read"]
  SESSION_TYPE = "filesystem"
  ```

* I only commit **safe code and templates**. No client secrets, no `.env`.

In a production setting, these values would live in a **secret manager** (for example, Azure Key Vault) or be replaced by **managed identities** and other secretless patterns.

---

## 📋 Step 1 – App Registration in Microsoft Entra ID

1. Go to **Entra admin center**: `https://entra.microsoft.com`.

2. Navigate to:
   `Identity → Applications → App registrations → New registration`.

3. Fill in:

   * **Name:** `IAM Fundamentals – Lab 2 (Flask Graph Me)`
   * **Supported account types:**
     `Accounts in this organizational directory only (Single tenant)`
   * **Redirect URI**

     * Platform: `Web`
     * URI: `http://localhost:5000/getAToken`

4. Click **Register**.

5. On the **Overview** page, capture:

   * **Application (client) ID** → `CLIENT_ID`
   * **Directory (tenant) ID** → `TENANT_ID`

6. Create a **client secret**:

   * Go to **Certificates & secrets → Client secrets**.
   * Click **New client secret**.
   * Description: `lab2 secret`
   * Choose an expiry (default is fine for the lab).
   * Click **Add**.
   * Immediately copy the **Value** (not the ID) → `CLIENT_SECRET`.

7. Configure **API permissions**:

   * Go to **API permissions → Add a permission**.
   * Choose **Microsoft Graph**.
   * Select **Delegated permissions**.
   * Find and add `User.Read`.
   * (Optional) If needed, click **Grant admin consent** for the tenant.

8. Confirm the **redirect URI**:

   * Go to **Authentication (Preview)**.
   * Ensure there is a Web redirect URI that matches exactly:

     ```text
     http://localhost:5000/getAToken
     ```

---

## 📋 Step 2 – Local Setup

All commands are from the Lab 2 folder on my Linux machine.

### 2.1 Virtual environment and dependencies

```bash
cd "Lab 2 - Call Microsoft Graph with OAuth2"

python3 -m venv .venv
source .venv/bin/activate

python --version
which python
```

Install dependencies:

```bash
pip install --upgrade pip
pip install Flask msal python-dotenv requests
```

(Optional but recommended) create `requirements.txt`:

```text
Flask
msal
python-dotenv
requests
```

### 2.2 Environment and config

Create `.env` in the lab folder and add `CLIENT_ID`, `CLIENT_SECRET`, `TENANT_ID`, and `FLASK_SECRET_KEY`.

`config.py` (shown above) loads these values and defines:

* `AUTHORITY`
* `REDIRECT_PATH` (`/getAToken`)
* `SCOPE` (`["User.Read"]`)

---

## 📋 Step 3 – Implementation

### 3.1 Flask app + MSAL auth code flow

`app.py`:

* Configures Flask with `SECRET_KEY` for sessions.

* Defines helpers:

  * `_build_msal_app()` – creates a `ConfidentialClientApplication`.
  * `_build_auth_code_flow()` – starts an auth code flow with the redirect URI and scopes.

* Routes:

  * `/` (**index**)

    * Shows a simple page with a link: **“Sign in and call Microsoft Graph”**.
  * `/login`

    * Starts the **auth code flow**, stores `flow` in session, and redirects to Entra’s login page.
  * `/getAToken`

    * Handles the redirect from Entra, completes the flow with `acquire_token_by_auth_code_flow`, stores `user` and `access_token` in the session, and redirects to `/graph_me`.
  * `/graph_me`

    * Uses the access token to call `https://graph.microsoft.com/v1.0/me` and renders the result in `graph_me.html`.
  * `/logout`

    * Clears the session and optionally redirects through Microsoft’s logout endpoint.

### 3.2 Templates

* `templates/index.html` – shows whether the user is signed in and links to `/login` or `/graph_me`.

* `templates/graph_me.html` – displays:

  * Display name
  * User principal name
  * ID (object ID)

* `templates/error.html` – pretty-prints any error dictionary as JSON for debugging.

---

## 📋 Step 4 – Testing

With the virtual environment active:

```bash
python app.py
```

Then:

1. Browse to `http://127.0.0.1:5000` or `http://localhost:5000`.
2. Click **“Sign in and call Microsoft Graph”**.
3. Sign in with my Cumulus Labs tenant account.
4. Approve the **permissions requested** screen for `User.Read`.
5. I’m redirected to `/graph_me` and see:

   * Display name
   * User principal name (UPN)
   * ID

This confirms the **auth code flow** worked and the **access token** is valid for Graph.

---

## 📈 Outcomes

After finishing this lab I can:

* Demonstrate a working **OAuth 2.0 authorization code flow** from Flask to Microsoft Entra ID.
* Explain how an app requests **delegated Graph permissions** like `User.Read`.
* Show a real example of using **access tokens** to call Microsoft Graph `/me`.
* Talk through **redirect URIs**, **client secrets**, and **AADSTS50011** errors from personal experience.

This lab pairs with Lab 1:

* **Lab 1:** “Who are you?” (ID token / authentication).
* **Lab 2:** “What can this app do on your behalf?” (access token + Graph scopes).

---

## 📷 Screenshots

| #  | Screenshot                                                                                                                                                                                                 | Description                                                                                                             |
|----|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| 1  | ![01-create-client-secret](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/01-create-client-secret.png?raw=1)              | Certificates & secrets blade showing the “Add a client secret” dialog for the Lab 2 app registration.                  |
| 2  | ![02-request-api-permissions](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/02-request-api-permissions.png?raw=1)       | Request API permissions pane for Microsoft Graph, selecting **Delegated permissions**.                                 |
| 3  | ![03-api-permissions-user-read](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/03-api-permissions-user-read.png?raw=1)   | API permissions blade with **Microsoft Graph → User.Read (Delegated)** configured for the app.                         |
| 4  | ![04-authentication-redirect-uris](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/04-authentication-redirect-uris.png?raw=1) | Authentication (Preview) blade listing web redirect URIs for the Lab 2 app registration.                               |
| 5  | ![05-edit-redirect-uri](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/05-edit-redirect-uri.png?raw=1)                   | Edit Redirect URI dialog where the URI is corrected to `http://localhost:5000/getAToken` / `http://127.0.0.1:5000…`.   |
| 6  | ![06-local-lab2-home](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/06-local-lab2-home.png?raw=1)                       | Local Lab 2 home page at `http://127.0.0.1:5000` showing “You are not signed in” and a link to sign in and call Graph. |
| 7  | ![07-microsoft-consent-screen](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/07-microsoft-consent-screen.png?raw=1)     | Microsoft “Permissions requested” dialog for **IAM Fundamentals – Lab 2 (Flask Graph Me)** requesting `User.Read`.     |
| 8  | ![08-graph-me-result](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/08-graph-me-result.png?raw=1)                       | Final `/graph_me` page showing Display name, User principal name, and ID returned from Microsoft Graph.                |
             
---

## 🧯 Errors & Troubleshooting

### 1. AADSTS50011 – Redirect URI mismatch

**What I saw**

After clicking “Sign in and call Microsoft Graph,” Entra redirected to an error page:

> AADSTS50011: The redirect URI `http://127.0.0.1:5000/getAToken` specified in the request does not match the redirect URIs configured for the application...

Screenshot:  
![Redirect URI mismatch error](https://github.com/miadco/IAM-Protocols/blob/main/Lab%202%3A%20Call%20Microsoft%20Graph%20with%20OAuth%202.0%20Authorization%20Code%20Flow/screenshots/09-redirect-uri-mismatch-error.png?raw=1)

**Root cause**

The redirect URI used by the app (`http://127.0.0.1:5000/getAToken`) did not exactly match the redirect URI configured in the app registration. Even small differences (localhost vs 127.0.0.1, missing path, trailing slash differences) will trigger this error.

**What I did**

1. Confirmed in `config.py` that:

   ```python
   REDIRECT_PATH = "/getAToken"


   so Flask was using `http://127.0.0.1:5000/getAToken` as the redirect URI.

2. Went to **Authentication (Preview)** for the Lab 2 app and **updated the Web redirect URI** to match exactly:

   ```text
   http://127.0.0.1:5000/getAToken
   ```

   or

   ```text
   http://localhost:5000/getAToken
   ```

   as long as it matched what the app was actually using.

3. Saved the change, restarted the Flask app, and repeated the sign-in flow.

After the redirect URIs matched, the AADSTS50011 error disappeared, and I landed on `/graph_me` with a valid response from Microsoft Graph.

---

## 💡 What I Learned

From this lab I can now say:

* I understand the difference between **OIDC (ID tokens)** and **OAuth 2.0 (access tokens)** in real code.
* I know how to configure **delegated permissions** like `User.Read` and how they relate to **scopes** requested by the app.
* I’ve seen the **authorization code flow** end-to-end:

  * Build auth URL → redirect to Entra
  * Sign in + consent
  * Receive auth code at `/getAToken`
  * Exchange code for tokens using a **client secret**
  * Call `https://graph.microsoft.com/v1.0/me` with the access token
* I understand why **redirect URI matching** matters and how it surfaces as `AADSTS50011`.
* I reinforced good habits around **secret handling** (using `.env`, not putting secrets in GitHub).

---

## 💼 Business Relevance

This lab maps directly to how real organizations wire up apps to Microsoft 365:

* Internal line-of-business apps that need to call **Microsoft Graph** on behalf of employees.
* Portals that rely on **SSO with Microsoft** and then fetch user data (profile, mailbox, calendar) using delegated permissions.
* Scenarios where security teams want apps to:

  * Never handle passwords directly.
  * Rely on **Entra ID** for identity assurance, Conditional Access, and MFA.
  * Use **access tokens** and **scopes** to tightly control what apps can do.

Being able to build and debug this flow makes me more hireable because I can:

* Talk about **how apps integrate with Entra and Microsoft Graph** at a concrete level, not just definitions.
* Show working code that respects **least privilege**, **delegated permissions**, and **secure secret handling**.
* Translate between architecture diagrams and implementation details when discussing **Zero Trust** and **identity-first security**.

---

## 🎤 Interview Talking Points

Some ways I can describe this lab in an interview:

* “I built a Flask app that uses the OAuth 2.0 authorization code flow with Microsoft Entra ID to obtain an access token and call Microsoft Graph `/me`.”
* “The app is registered as a confidential client; it uses a client secret and a redirect URI of `/getAToken` to complete the token exchange securely.”
* “I configured the app with the delegated permission `User.Read`, then verified that the returned access token is accepted by Graph when calling `/v1.0/me`.”
* “I ran into an `AADSTS50011` redirect URI mismatch, tracked it down to a localhost vs 127.0.0.1 mismatch, and fixed it by aligning the app registration with the actual redirect URI.”
* “In a production version, I’d move secrets into Key Vault, use HTTPS everywhere, and extend the pattern to other scopes like `Mail.Read` and `Calendars.Read` while keeping least privilege in mind.”

---

## 🙏 Acknowledgments

This lab was built using AI-assisted development as a learning accelerator.

AI helped with:

* Structuring the lab and the README.
* Drafting the Flask + MSAL patterns.
* Debugging the `AADSTS50011` redirect URI issue.

I own:

* The actual troubleshooting and configuration in my tenant.
* Understanding how the authorization code flow works end-to-end.
* The ability to explain **why** each step exists and how it maps to real IAM and Microsoft 365 scenarios.

This lab sits on top of Lab 1 and moves me one step closer to real-world **IAM + Microsoft 365 application integration**.
