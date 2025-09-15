from flask import Flask, render_template, request, session, redirect, send_file, abort,url_for,send_from_directory, render_template_string
import os
from html import escape 

app = Flask(__name__)
app.secret_key = "cerberus_lab_secret"


# Simple user database-----------------------------------------------------------------------------------------------------
users = {
    "user": {"password": "user321", 
               "email": "user@cerberus.lab",
               "role": "user"},

    "admin": {"password": "admin321", 
              "email": "admin@cerberus.lab",
              "role": "admin"}
}



# Sample sensitive files--------------------------------------------------------------------------------------------------
SENSITIVE_FILES = {
    "secret.txt": "TOPSECRET: Cerberus Project Alpha",
    "secret.env": "API_KEY=12345\nDB_PASSWORD=supersecret"
}

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = users.get(username)
    if user and user["password"] == password:
        session['username'] = username
        return redirect("/dashboard")
    # If login fails, render index.html with an error message
    return render_template("index.html", error="Invalid credentials! Please enter valid username and password.")



# Flags for challenges (IDOR, Path Traversal, LFI, XSS)-----------------------------------------------------------------
FLAGS = {
    "idor": "THM{ID0R_C4NB3_AND_I$_SC4RY_F44M}",          
    "path": "THM{M4YB3_0D3SSYU$_ShOULdVE_D0N3_P4THtRAV3R$4L}",
    "lfi":  "THM{!T_A1NT_N0_J0K3_CH4T_TH!$_LF!}",
    "xss":  "THM{P0LYPH3MVS_G0T_TH4T_X$$}",
    "csrf": "THM{AY0_D1D_Y0U_JU5T_C$RF_M3?}"
}

# set this constant or use an environment variable 
EXPECTED_SECRET = os.getenv("CERBERUS_SECRET", "A wise man turns danger into opportunity; a fool is swallowed by what he cannot foresee")
FINAL_FLAG = os.getenv("CERBERUS_FLAG", FLAGS["path"])


# Dashboard and Logout ---------------------------------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    if not session.get('username'):
        return redirect("/")
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect("/")


# --------- IDOR Vulnerability Implementation --------------------------------------------------------------------------
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "")
    user = users.get(user_id)
    flag = None
    if user and user_id == "admin":
        flag = FLAGS.get("idor")
    if user:
        return render_template("profile.html", user=user, user_id=user_id, flag=flag)
    return "User not found"



# --------- Path Traversal Vulnerability Implementation ----------------------------------------------------------------
@app.route("/download")
def download():
    if 'username' not in session:
        return redirect(url_for('login'))

    # use 'file' for the query param (keep consistent with links)
    file_name = request.args.get("file", "").strip()
    if not file_name:
        return render_template("download.html", file=None, content=None, error=None, show_submit=False)

    raw_path = os.path.normpath(os.path.join("reports", file_name))
    content_text = None
    error = None
    show_submit = False

    try:
        if not os.path.exists(raw_path):
            error = "File not found."
        else:
            with open(raw_path, "rb") as f:
                raw_bytes = f.read()

            # show readable ASCII parts (do NOT decode or process secrets for the player)
            try:
                content_text = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                content_text = str(raw_bytes[:1024])

            content_text = escape(content_text)

            # Show submission only when the file name *is* the secret file (adjust as needed)
            if os.path.basename(raw_path).lower() == "secret.txt":
                show_submit = True

    except Exception as e:
        error = f"Error reading file: {e}"

    return render_template("download.html",
                           file=file_name,
                           content=content_text,
                           error=error,
                           show_submit=show_submit)


# --------- Secret Submission and Validation ---------
@app.route("/submit_secret", methods=["POST"])
def submit_secret():
    if 'username' not in session:
        return redirect(url_for('login'))

    submitted = (request.form.get("decoded_secret") or "").strip()

    # Load expected plaintext from an env var (safer) with a sensible default for local testing
    EXPECTED = os.getenv("CERBERUS_SECRET", "A wise man turns danger into opportunity; a fool is swallowed by what he cannot foresee")

    if not submitted:
        return render_template("pathTraversal_Result.html", success=False, message="No secret submitted.")

    if submitted == EXPECTED:
        final_flag = FLAGS.get("path", "FLAG_NOT_SET")
        return render_template("pathTraversal_Result.html", success=True, flag=final_flag)
    else:
        return render_template("pathTraversal_Result.html", success=False, message="Decoded secret did not match. Try again.")



# ---------- LFI Vulnerability implementation (Last resort)-----------------------------------------------
@app.route("/view")
def view_lfi():
    log = request.args.get("log")
    content = None
    error = None

    if log:
        try:
            # Only allow files inside the logs folder for safety
            file_path = f"logs/{log}"
            with open(file_path, "r") as f:
                file_content = f.read()

            # Dangerous: render template so Jinja code can execute (simulated LFI)
            content = render_template_string(file_content)

        except Exception:
            error = "Cannot open or render file"

    return render_template("view.html", content=content, error=error)


@app.route("/submit_flag", methods=["GET", "POST"])
def submit_flag():
    success = False
    flag = None
    message = ""
    expected = "Time, which sees all things, has found you out against your will"
    if request.method == "POST":
        submitted = (request.form.get("secret") or "").strip()
        if not submitted:
            message = "No secret submitted."
        elif submitted == expected:
            success = True
            flag = FLAGS.get("lfi", "FLAG_NOT_SET")
        else:
            message = "Incorrect, try again!"
    return render_template("lfi_result.html", success=success, flag=flag, message=message)


# --------- Reflected XSS Endpoint ---------
@app.route("/search")
def search():
    query = request.args.get("query", "")
    flag = None
    # Example: Show flag if the payload is a classic XSS
    if query.strip() == '<script>alert(1)</script>':
        flag = FLAGS.get("xss", "FLAG_NOT_SET")
    return render_template("search.html", query=query, flag=flag)




# --------- CSRF Vulnerability Implementation --------------------------------------------------------------------------
@app.route("/changeEmail", methods=["GET", "POST"])
def change_email():
    flag = None
    message = ""
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        new_email = request.form.get("email", "")
        # Vulnerable: No CSRF protection!
        users[session['username']]['email'] = new_email
        # Show flag for any email change via POST
        flag = FLAGS.get("csrf", "FLAG_NOT_SET")
    return render_template("changeEmail.html", flag=flag, message=message, email=users[session['username']]['email'])




























