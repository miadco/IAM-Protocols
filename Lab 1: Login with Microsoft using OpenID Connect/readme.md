# IAM Protocols - Lab 1: Login with Microsoft using OpenID Connect

## 📌 Overview

In this lab I built a **“Sign in with Microsoft”** experience using **OpenID Connect (OIDC)** and the **authorization code flow**.

I wired a small **Flask** app to:

* Redirect me to **Microsoft Entra ID** for sign in
* Handle the **authorization code** callback on my app
* Exchange that code for an **ID token** using **msal**
* Render the **ID token claims** in my browser so I can see exactly what Entra is asserting about my identity

The point of this lab is not UI polish. The point is to prove that I understand how a real web app talks to Entra using OIDC.

---

## 🎯 Objectives

By the end of this lab I have:

* Registered a **confidential client** app in **Microsoft Entra ID**
* Configured a **web redirect URI** for a local Flask app
* Enabled **ID tokens** and created a **client secret**
* Implemented `/login` and `/auth/redirect` with **msal** and the authorization code flow
* Displayed **ID token claims** to prove authentication worked end to end

---

## 🧠 Key Concepts

* **OpenID Connect (OIDC)**: Identity layer on top of OAuth 2.0 used for authentication
* **Authorization Code Flow**: Browser-based redirect flow where my backend exchanges a short-lived code for tokens
* **ID Token**: A JWT that proves *who I am* (subject, tenant, issuer, audience, etc.)
* **Confidential Client**: A server-side application that can safely hold a client secret
* **App Registration**: The configuration in Entra that defines how my app integrates (IDs, redirect URIs, secrets, tokens)
* **MSAL for Python**: Library that simplifies acquiring tokens from the Microsoft identity platform

---

## 🧠 Mental Model

I treat this lab as a **3-step handshake** between my app and Entra:

1. **My app never touches passwords**
   When I click “Sign in with Microsoft,” my app builds an authorization URL with `client_id`, `redirect_uri` and `scope`, then redirects my browser to Microsoft.

2. **Microsoft handles identity**
   Microsoft authenticates me and, if everything checks out, sends my browser back to `/auth/redirect` on my app with an **authorization code**.

3. **My app proves it is trusted**
   On `/auth/redirect`, my app uses the **client secret** to exchange that code for an **ID token**. If the issuer, audience, and tenant claims are correct, I can trust the identity information inside the token.

The “success condition” for this lab is very concrete:
I sign in, get redirected back to my app, and see my **ID token claims** rendered on a page that I control.

---

## 🗂 Repository Structure

```text
IAM Protocols - Lab 1 - OIDC Login with Microsoft/
├── app/
│   ├── __init__.py              # Flask app, OIDC flow, routes
│   └── templates/
│       ├── base.html            # Shared layout
│       ├── index.html           # Landing page with “Sign in with Microsoft”
│       └── profile.html         # Displays ID token claims
├── evidence/                    # Screenshots for this lab
├── config_example.py            # Safe template (no real secrets)
├── config.py                    # Real values, local only (gitignored)
├── requirements.txt             # Flask + msal
├── .gitignore
└── README.md
```

---

## 🔒 Safety & Secrets

* `config.py` is **ignored by Git** via `.gitignore` and never committed

* `config.py` holds my Entra-specific values:

  * `CLIENT_ID`
  * `TENANT_ID`
  * `CLIENT_SECRET`
  * `REDIRECT_URI`
  * `SCOPES`

* I must use the **client secret value**, not the **secret ID**

* For this lab, storing secrets in `config.py` is acceptable because everything is local and short-lived

* In production I would:

  * Move secrets to **Key Vault** or another secret manager
  * Use **managed identities** or other secretless flows where possible

* When I am done with the lab I can:

  * Delete the **client secret** and/or
  * Delete the entire **app registration** in Entra

---

## 📋 Step 1 – App Registration

1. I go to the Entra admin center:
   `https://entra.microsoft.com`
2. I navigate to:
   **Identity → Applications → App registrations → New registration**
3. I fill in:

   * **Name**: `IAM Protocols - Lab 1 OIDC`
   * **Supported account types**:
     `Accounts in this organizational directory only (Single tenant)`
   * **Redirect URI**:

     * Platform: `Web`
     * URI: `http://localhost:5000/auth/redirect`
4. I click **Register**.
5. On the **Overview** page I capture:

   * **Application (client) ID** → `CLIENT_ID`
   * **Directory (tenant) ID** → `TENANT_ID`
6. I create a client secret:

   * Go to **Certificates & secrets → Client secrets**
   * Click **New client secret**
   * Description: `Lab1-local-flask`
   * Choose an expiry
   * Click **Add**
   * Immediately copy the **Value** (this is the actual secret) → `CLIENT_SECRET`
7. I enable ID tokens:

   * Go to **Authentication**
   * Open the **Settings** tab
   * Under **Implicit grant and hybrid flows**, I check:

     * `ID tokens (used for implicit and hybrid flows)`
   * I click **Save**

At this point I have the three values my Flask app needs: `CLIENT_ID`, `TENANT_ID`, and `CLIENT_SECRET`.

---

## 📋 Step 2 – Local Setup

All commands below are run from my Linux terminal.

### 2.1 Create the folder structure

```bash
mkdir "IAM Protocols - Lab 1 - OIDC Login with Microsoft"
cd "IAM Protocols - Lab 1 - OIDC Login with Microsoft"

mkdir -p app/templates
mkdir -p evidence

touch README.md
```

### 2.2 `.gitignore`

```bash
cat << 'EOF' > .gitignore
.venv/
__pycache__/
config.py
.env
EOF
```

### 2.3 Virtual environment and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate

which python
python --version
```

If the venv fails to create, I fix that in the troubleshooting section (below), then come back here.

I create `requirements.txt`:

```bash
cat << 'EOF' > requirements.txt
Flask
msal
EOF

pip install -r requirements.txt
```

### 2.4 Configuration files

I create a safe example config that I can commit:

```bash
cat << 'EOF' > config_example.py
"""
Example configuration for:
IAM Protocols - Lab 1: Login with Microsoft using OpenID Connect

I fill these in after I create the App Registration in Entra ID.
"""

CLIENT_ID = "YOUR_CLIENT_ID"
TENANT_ID = "YOUR_TENANT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"

REDIRECT_URI = "http://localhost:5000/auth/redirect"
SCOPES = ["User.Read"]
EOF
```

I then create my real local config by copying the template:

```bash
cp config_example.py config.py
```

Finally I edit `config.py` and replace the placeholders:

```python
"""
Real configuration for:
IAM Protocols - Lab 1: Login with Microsoft using OpenID Connect
"""

CLIENT_ID = "my-real-client-id-guid"
TENANT_ID = "my-real-tenant-id-guid"
CLIENT_SECRET = "my-real-client-secret-value"

REDIRECT_URI = "http://localhost:5000/auth/redirect"
SCOPES = ["User.Read"]
```

---

## 📋 Step 3 – Implementation

### 3.1 Flask app and OIDC flow

`app/__init__.py`:

```python
from flask import Flask, render_template, redirect, request
import msal
import config

app = Flask(__name__)

# Simple dev secret for Flask sessions (local lab only)
app.secret_key = "dev_secret_change_me"


def build_msal_app():
    """Create a ConfidentialClientApplication using config values."""
    authority = f"https://login.microsoftonline.com/{config.TENANT_ID}"
    return msal.ConfidentialClientApplication(
        client_id=config.CLIENT_ID,
        authority=authority,
        client_credential=config.CLIENT_SECRET,
    )


def build_auth_url():
    """Build the authorization URL to redirect the user to Microsoft."""
    msal_app = build_msal_app()
    return msal_app.get_authorization_request_url(
        scopes=config.SCOPES,
        redirect_uri=config.REDIRECT_URI,
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login():
    # Step 1 of OIDC: redirect user to Microsoft for sign in
    auth_url = build_auth_url()
    return redirect(auth_url)


@app.route("/auth/redirect")
def auth_redirect():
    # Step 2 of OIDC: Microsoft redirects back here with an auth code
    code = request.args.get("code")
    if not code:
        return "No authorization code found in redirect.", 400

    msal_app = build_msal_app()
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=config.SCOPES,
        redirect_uri=config.REDIRECT_URI,
    )

    if "id_token_claims" not in result:
        error_desc = result.get("error_description") or str(result)
        return f"Login failed. Details: {error_desc}", 400

    claims = result["id_token_claims"]
    return render_template("profile.html", claims=claims)
```

### 3.2 Templates

`app/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>IAM Protocols - Lab 1</title>
    <style>
        body {
            background-color: #111827;
            color: #e5e7eb;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        .container {
            max-width: 900px;
            margin: 3rem auto;
            padding: 2rem 3rem;
            background-color: #020617;
            border-radius: 0.75rem;
        }
        h1 {
            margin-bottom: 0.5rem;
        }
        .subtitle {
            color: #9ca3af;
            margin-bottom: 1.5rem;
        }
        .button-primary {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            background-color: #2563eb;
            color: white;
            text-decoration: none;
            font-weight: 500;
        }
        pre {
            background-color: #020617;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
        }
    </style>
</head>
<body>
<div class="container">
    {% block content %}{% endblock %}
</div>
</body>
</html>
```

`app/templates/index.html`:

```html
{% extends "base.html" %}

{% block content %}
<h1>IAM Protocols - Lab 1: Login with Microsoft (OIDC)</h1>
<p class="subtitle">
    This is my local test app for validating the OIDC authorization code flow with Microsoft Entra ID.
</p>

<a class="button-primary" href="/login">Sign in with Microsoft</a>
{% endblock %}
```

`app/templates/profile.html`:

```html
{% extends "base.html" %}

{% block content %}
<h1>Logged in with Microsoft</h1>
<p class="subtitle">
    ID token claims returned from Microsoft Entra ID (shown as JSON).
</p>

<pre>{{ claims | tojson(indent=2) }}</pre>
{% endblock %}
```

---

## 📋 Step 4 – Testing

From the lab root, with my virtual environment active:

```bash
export FLASK_APP=app
flask run
```

I test the flow:

1. I open `http://127.0.0.1:5000` in my browser.
2. I click **Sign in with Microsoft**.
3. I sign in and grant consent if needed.
4. After Microsoft redirects back to `http://localhost:5000/auth/redirect`, I expect to see:

   * A page titled **“Logged in with Microsoft”**
   * My **ID token claims** rendered as pretty-printed JSON

If something goes wrong, I capture the error and fix it (see the troubleshooting section).

---

## 📈 Outcomes

After finishing this lab I can:

* Demonstrate a working **Login with Microsoft** experience using OIDC and Flask
* Show a real **confidential client** app that I registered and configured in Entra
* Explain and show code for:

  * Building an authorization URL with **msal**
  * Handling the authorization code callback
  * Exchanging the code for an ID token on the backend
* Walk through the **ID token claims** in my own browser and explain what they mean
* Use this project as **evidence** in:

  * My GitHub portfolio
  * LinkedIn posts and carousels
  * Interview conversations

---

## 📷 Screenshots

| # | Screenshot | Description |
|---|------------|-------------|
| 1 | ![01-register-oidc-app](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/01-register-oidc-app.png) | App registration in Microsoft Entra ID for **IAM Protocols – Lab 1 OIDC**, showing single-tenant selection and the initial redirect URI `http://localhost:5000/auth/redirect`. |
| 2 | ![02-configure-redirect-uri](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/02-configure-redirect-uri.png) | **Authentication → Redirect URI configuration** blade with the Web redirect URI pointing to the Flask app’s `/auth/redirect` endpoint. |
| 3 | ![03-enable-id-tokens](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/03-enable-id-tokens.png) | **Authentication → Settings** tab with **ID tokens** enabled so the app can receive an ID token via the authorization code flow. |
| 4 | ![04-create-client-secret](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/04-create-client-secret.png) | **Certificates & secrets** blade showing creation of a client secret (e.g., “Local Flask OIDC”) that the Flask app uses as its confidential credential. |
| 5 | ![05-flask-oidc-code](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/05-flask-oidc-code.png) | Terminal view of the Flask app code, including `build_msal_app`, `build_auth_url`, and the `/login` and `/auth/redirect` routes wired to MSAL. |
| 6 | ![06-local-login-page](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/06-local-login-page.png) | Local test app home page at `http://127.0.0.1:5000` with the **“Sign in with Microsoft”** button that starts the OIDC flow. |
| 7 | ![07-microsoft-consent-screen](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/07-microsoft-consent-screen.png) | Microsoft sign-in and consent screen for **IAM Protocols – Lab 1 OIDC**, requesting permission to sign in and read the user profile. |
| 8 | ![08-logged-in-with-microsoft](https://github.com/miadco/IAM-Protocols/blob/main/Lab%201%3A%20Login%20with%20Microsoft%20using%20OpenID%20Connect/screenshots/08-logged-in-with-microsoft.png) | Successful sign-in view from the Flask app showing **“Logged in with Microsoft”** and a JSON subset of ID token claims returned by Entra ID. |


---

## 🧯 Errors & Troubleshooting

### 1. Virtual environment failed to create (`ensurepip is not available`)

**What I saw**

When I ran:

```bash
python3 -m venv .venv
```

I got:

```text
The virtual environment was not created successfully because ensurepip is not
available. On Debian/Ubuntu systems, you need to install the python3-venv
package...
```

**What I did**

```bash
# Install venv support for this Python version
sudo apt install python3.12-venv

# Remove any broken venv and recreate it
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate

which python
python --version
pip install -r requirements.txt
```

After that, the venv and dependencies worked correctly.

---

### 2. `AADSTS7000215: Invalid client secret provided`

**What I saw**

After authenticating, my browser showed:

```text
Login failed. Details: AADSTS7000215: Invalid client secret provided.
Ensure the secret being sent in the request is the client secret value,
not the client secret ID...
```

**Root cause**

In `config.py` I had accidentally used the **secret ID** (or an old value) instead of the **secret value** that is shown only once when I create the secret in Entra.

**What I did**

1. I went back to Entra → **App registrations → My lab app → Certificates & secrets → Client secrets**.

2. I created a new secret and copied the **Value** immediately.

3. I updated `config.py`:

   ```python
   CLIENT_SECRET = "my-correct-client-secret-value"
   ```

4. I restarted Flask:

   ```bash
   export FLASK_APP=app
   flask run
   ```

After that, the token exchange succeeded and I reached the profile page.

---

### 3. Internal Server Error on `/auth/redirect`

**What I saw**

At one point, after signing in, I landed on a generic:

```text
Internal Server Error

The server encountered an internal error and was unable to complete your request.
```

**Root cause**

While editing `app/__init__.py` I accidentally pasted terminal text (for example `clear`) or partial code, which left the file in a broken state.

**What I did**

1. I reopened `app/__init__.py` and compared it to my intended version of the file.

2. I made sure there was:

   * A clean set of imports at the top
   * Fully defined functions and routes
   * No stray shell text or incomplete lines at the bottom

3. I ran a quick syntax check:

   ```bash
   python -m py_compile app/__init__.py
   ```

4. I restarted Flask and retried the sign-in flow.

Once the file was clean, the internal server error disappeared and I saw my token claims.

---

### 4. Template file names treated as commands

**What I saw**

At one point I typed:

```bash
base.html  index.html  profile.html
```

in the terminal and got:

```text
base.html: command not found
```

**Root cause**

I accidentally pasted a list of filenames directly into the shell instead of using an editor.

**What I did**

I ignored the error (it is harmless) and made sure the actual files existed under:

```text
app/templates/base.html
app/templates/index.html
app/templates/profile.html
```

The app worked fine once the templates were in place.

---

## 💡 What I Learned

From this lab I can now say:

* I know how to configure a **single-tenant web app** in Microsoft Entra with a proper redirect URI and ID tokens enabled.
* I understand the difference between **ID tokens** (who I am) and **access tokens** (what I can access).
* I have seen the **authorization code flow** end-to-end in my own browser:

  * Redirect to Microsoft
  * Callback to `/auth/redirect` with a `code`
  * Backend token exchange using a client secret
* I can read key OIDC claims and explain them:

  * `aud` tells me which app the token is for
  * `iss` and `tid` identify the authority and tenant
  * `oid` is the stable user object ID
  * `preferred_username` shows the login identifier
* I understand why secret handling details matter:

  * Using the **secret value** instead of the **secret ID**
  * Keeping secrets in `config.py` only for local labs, and moving them to a proper secret store in production

---

## 💼 Business Relevance

This lab maps directly to real-world scenarios:

* Internal apps that require **corporate SSO** with Microsoft
* External portals that offer **“Sign in with Microsoft”** as an identity provider
* Architectures that rely on:

  * Centralized identity and access in **Entra ID**
  * **Conditional Access** and **MFA** policies enforced by the IdP
  * Applications that never handle passwords directly

Because I built and debugged this myself, I can walk into a conversation and talk about:

* Why it is safer to offload authentication to Microsoft
* How token-based identity supports **Zero Trust** (identity as the perimeter)
* How app registrations, redirect URIs, and token validation all fit together

---

## 🎤 Interview Talking Points

Some ways I can talk about this lab in interviews:

* “I built a Flask web app that uses the **OpenID Connect authorization code flow** to authenticate users with Microsoft Entra ID.”
* “The app is registered as a **confidential client**, and it uses a client secret to exchange the authorization code for an ID token.”
* “My `/login` route builds an authorization URL with **msal** and redirects the user to Microsoft, while `/auth/redirect` validates the `code` and calls `acquire_token_by_authorization_code` to get tokens.”
* “I render the **ID token claims** so I can walk a hiring manager through each claim and explain what it means for identity and access.”
* “In a production version I would move secrets into **Key Vault** or use managed identities, and I would replace the raw claims page with a proper signed-in experience that authorizes users based on claims.”

---

## 🙏 Acknowledgments

This lab was built using AI-assisted development (Claude for architecture,  
ChatGPT for debugging) as a deliberate learning accelerator.  

**AI helped with:**

- Flask routing patterns and MSAL integration  
- Debugging AADSTS error codes  
- README structure and markdown formatting  

**I own:**

- All troubleshooting and problem-solving decisions  
- Understanding of OIDC flow and token validation  
- Ability to explain every line of code  

This lab demonstrates my ability to use modern tools to ship working code while maintaining deep  
technical understanding.

I also referenced:

- Microsoft identity platform documentation and MSAL Python samples for details on the authorization code flow  
- Flask and Jinja2 documentation for building and templating the web app  
