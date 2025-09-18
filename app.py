from flask import Flask, render_template, request, session, redirect, send_file, abort,url_for,send_from_directory, render_template_string
import os
import re
from html import escape 

app = Flask(__name__)
app.secret_key = "cerberus_lab_secret"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Azure's port if provided
    app.run(host="0.0.0.0", port=port, debug=False)


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


# flask routes for login and home page-------------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html") #the login page


#handling login by validating username and password
@app.route("/login", methods=["POST"])
def login():

    #extracting values from user input
    username = request.form.get("username")
    password = request.form.get("password")

    #validating credentials against the users dictionary
    user = users.get(username)

    #check if user exists and password matches
    if user and user["password"] == password:
        session['username'] = username
        return redirect("/dashboard") #redirect to dashboard on successful login
    
    # If login fails, reload the login page with an error message
    return render_template("index.html", error="Invalid credentials! Please enter valid username and password.")


# Flags for challenges (IDOR, Path Traversal, LFI, XSS, CSRF)----------------------------------------------------------------
FLAGS = {
    "idor": "THM{ID0R_C4NB3_AND_I$_SC4RY_F44M}",          
    "path": "THM{M4YB3_0D3SSYU$_ShOULdVE_D0N3_P4THtRAV3R$4L}",
    "lfi":  "THM{!T_A1NT_N0_J0K3_CH4T_TH!$_LF!}",
    "xss":  "THM{P0LYPH3MVS_G0T_TH4T_X$$}",
    "csrf": "THM{AY0_D1D_Y0U_JU5T_C$RF_M3?}"
}


#setting variables for the secret and final flag for path traversal challenge (as another method of configuration)
EXPECTED_SECRET = os.getenv("CERBERUS_SECRET", "A wise man turns danger into opportunity; a fool is swallowed by what he cannot foresee")
FINAL_FLAG = os.getenv("CERBERUS_FLAG", FLAGS["path"])


# Dashboard and Logout ---------------------------------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    # Ensure user is logged in, if not redirect to login
    if not session.get('username'):
        return redirect("/")
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    #logout is done by clearing the username from the session using session.pop()
    session.pop('username', None)
    return redirect("/")


# --------- IDOR Vulnerability Implementation --------------------------------------------------------------------------
@app.route("/profile")
def profile():
    #It reads user_id from query parameter and returns arbitrary user's profile.
    user_id = request.args.get("user_id", "") #use 'user_id' for the query param (keep consistent with links)
    user = users.get(user_id)
    flag = None

    # Show flag if admin profile is accessed
    #check based purely on user_id value rather than on session auth
    if user and user_id == "admin":
        flag = FLAGS.get("idor")

    #return to the profile page with user details and if admin, along with the flag
    if user:
        return render_template("profile.html", user=user, user_id=user_id, flag=flag)
    
    #if user not found, return an error message
    return "User not found"



# --------- Path Traversal Vulnerability Implementation ----------------------------------------------------------------
@app.route("/download")
def download():
    # Ensure user is logged in, if not redirect to login
    if 'username' not in session:
        return redirect(url_for('login'))

    # Accept the 'file' query parameter for the file name
    file_name = request.args.get("file", "").strip()

    # If no file is specified, reload download page with no content and no submit option for the flag
    if not file_name:
        return render_template("download.html", file=None, content=None, error=None, show_submit=False)

    # Normalize the path to prevent simple traversal, but still allow complex ones
    raw_path = os.path.normpath(os.path.join("reports", file_name))
    content_text = None
    error = None
    show_submit = False

    try:
        # If file doesn't exist, return file not found error
        if not os.path.exists(raw_path):
            error = "File not found."
        else:
            # Read raw bytes from file
            with open(raw_path, "rb") as f:
                raw_bytes = f.read()

            # show readable ASCII parts (do NOT decode or process secrets for the player)
            try:
                content_text = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                content_text = str(raw_bytes[:1024]) # If decoding fails, show the first chunk of bytes as a fallback

            # Escape content to prevent XSS when displaying in HTML
            content_text = escape(content_text)

            # Show submission only when the file name *is* the secret file (adjust as needed)
            if os.path.basename(raw_path).lower() == "secret.txt":
                show_submit = True  # using os.path.basename compares the file name only; a path traversal can still reach secret.txt 

    # error handling for file read issues
    except Exception as e:
        error = f"Error reading file: {e}"

    # Render the download page with file content or error message
    return render_template("download.html",
                           file=file_name,
                           content=content_text,
                           error=error,
                           show_submit=show_submit)

# Secret Submission and Validation for Path Traversal Challenge
@app.route("/submit_secret", methods=["POST"])
def submit_secret():
    # Ensure user is logged in, if not redirect to login
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get the submitted secret from the form
    submitted = (request.form.get("decoded_secret") or "").strip()

    # Load expected plaintext from an env var (safer) with a sensible default for local testing
    EXPECTED = os.getenv("CERBERUS_SECRET", "A wise man turns danger into opportunity; a fool is swallowed by what he cannot foresee")

    # Check if the submitted secret is empty
    if not submitted:
        return render_template("pathTraversal_Result.html", success=False, message="No secret submitted.")

    # Validate the submitted secret against the expected value
    if submitted == EXPECTED:
        final_flag = FLAGS.get("path", "FLAG_NOT_SET")
        # If correct, show success and the final flag
        return render_template("pathTraversal_Result.html", success=True, flag=final_flag)
    else:
        # If incorrect, show failure message
        return render_template("pathTraversal_Result.html", success=False, message="Decoded secret did not match. Try again.")



# ---------- LFI Vulnerability implementation (Last resort)------------------------------------------------------------------
@app.route("/view")
def view_lfi():
    # Ensure user is logged in, if not redirect to login
    log = request.args.get("log")
    content = None
    error = None

    if log:
        try:
            # Only allow files inside the logs folder for safety
            file_path = f"logs/{log}"
            with open(file_path, "r") as f:
                file_content = f.read()

            # Dangerous: render template so Jinja code can execute (simulated LFI) - not described in challenge !!!
            content = render_template_string(file_content)

        # Handle file not found and other errors
        except Exception:
            error = "Cannot open or render file"

    # Render the view page with file content or error message
    return render_template("view.html", content=content, error=error)

# Submission and Validation for LFI Challenge
@app.route("/submit_flag", methods=["GET", "POST"])
def submit_flag():
    success = False
    flag = None
    # Default message
    message = ""
    # Expected secret phrase for LFI challenge
    expected = "Time, which sees all things, has found you out against your will"

    # Process form submission
    if request.method == "POST":
        # Get the submitted secret from the form
        submitted = (request.form.get("secret") or "").strip()
        if not submitted:
            message = "No secret submitted."
        # Check if the submitted secret matches the expected value
        elif submitted == expected:
            success = True
            flag = FLAGS.get("lfi", "FLAG_NOT_SET")
        else:
            message = "Incorrect, try again!"

    # Render the result page with success status, flag, and message
    return render_template("lfi_result.html", success=success, flag=flag, message=message)



# --------- Reflected XSS Vulnerability Implementation ------------------------------------------------------------------
@app.route("/search")
def search():
    # Accept the 'query' parameter from the URL
    query = request.args.get("query", "")
    flag = None

    # Show flag if the query contains a script tag (case insensitive)
    if re.search(r'<script\b[^>]*>(.*?)</script>', query, flags=re.IGNORECASE | re.DOTALL):
        flag = FLAGS.get("xss", "FLAG_NOT_SET")

    # Render the search page with the query and flag (if any)
    return render_template("search.html", query=query, flag=flag)




# --------- CSRF Vulnerability Implementation --------------------------------------------------------------------------
@app.route("/changeEmail", methods=["GET", "POST"])
def change_email():
    flag = None
    message = ""
    # Ensure user is logged in, if not redirect to login
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    if request.method == "POST":
        new_email = request.form.get("email", "")
        users[username]['email'] = new_email
        flag = FLAGS.get("csrf", "FLAG_NOT_SET")
        
        # Reset email to default after showing the flag
        if username == "user":
            users[username]['email'] = "user@cerberus.lab"
        elif username == "admin":
            users[username]['email'] = "admin@cerberus.lab"
            
    return render_template("changeEmail.html", flag=flag, message=message, email=users[username]['email'])










