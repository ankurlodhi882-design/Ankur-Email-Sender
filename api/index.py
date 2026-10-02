import os
import re
import time
import ssl
import random
import secrets
import smtplib

from functools import wraps
from email.message import EmailMessage

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
)


# =========================================================
# IMPORTANT:
# index.py is inside /api
# templates and static are one level above /api
# =========================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
    static_url_path="/static",
)


# =========================================================
# SECRET KEY
# =========================================================

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)


# =========================================================
# LOGIN
# =========================================================

LOGIN_USER = os.getenv(
    "LOGIN_USER",
    "admin"
)

LOGIN_PASSWORD = os.getenv(
    "LOGIN_PASSWORD",
    "change-this-password"
)


# =========================================================
# SMTP
# =========================================================

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com"
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "465"
    )
)


# =========================================================
# SENDING SETTINGS
# =========================================================

MAX_RECIPIENTS = int(
    os.getenv(
        "MAX_RECIPIENTS",
        "50"
    )
)

MIN_DELAY = float(
    os.getenv(
        "MIN_DELAY_SECONDS",
        "1"
    )
)


# =========================================================
# EMAIL REGEX
# =========================================================

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# CHECK EMAIL
# =========================================================

def valid_email(email):

    return bool(
        EMAIL_RE.match(
            email.strip()
        )
    )


# =========================================================
# LOGIN DECORATOR
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get(
            "authenticated"
        ):

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# PARSE EMAILS
# =========================================================

def parse_recipients(raw):

    parts = re.split(
        r"[\s,;]+",
        raw or ""
    )

    recipients = []

    invalid = []

    seen = set()


    for email in parts:

        email = email.strip()

        if not email:
            continue


        if valid_email(email):

            key = email.lower()

            if key not in seen:

                seen.add(key)

                recipients.append(
                    email
                )

        else:

            invalid.append(
                email
            )


    return recipients, invalid


# =========================================================
# SPINTAX
#
# Example:
#
# {Hi|Hello} {name}
#
# =========================================================

def expand_spintax(text):

    pattern = re.compile(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    )


    def replace(match):

        options = (
            match.group(1)
            .split("|")
        )

        return random.choice(
            options
        )


    for _ in range(10):

        new_text = pattern.sub(
            replace,
            text
        )

        if new_text == text:

            break

        text = new_text


    return text


# =========================================================
# SEND EMAIL
# =========================================================

def send_one(
    sender_name,
    sender_email,
    app_password,
    recipient,
    subject,
    body
):

    message = EmailMessage()


    message["From"] = (
        f"{sender_name} "
        f"<{sender_email}>"
    )


    message["To"] = recipient

    message["Subject"] = subject


    message.set_content(
        body
    )


    context = (
        ssl.create_default_context()
    )


    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=30
    ) as smtp:

        smtp.login(
            sender_email,
            app_password
        )

        smtp.send_message(
            message
        )


# =========================================================
# HOME
# =========================================================

@app.get("/")
@login_required
def index():

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# =========================================================
# LOGIN
# =========================================================

@app.get("/login")
def login():

    if session.get(
        "authenticated"
    ):

        return redirect(
            url_for("index")
        )


    return render_template(
        "login.html"
    )


# =========================================================
# LOGIN POST
# =========================================================

@app.post("/login")
def do_login():

    username = request.form.get(
        "username",
        ""
    )

    password = request.form.get(
        "password",
        ""
    )


    if (
        secrets.compare_digest(
            username,
            LOGIN_USER
        )
        and
        secrets.compare_digest(
            password,
            LOGIN_PASSWORD
        )
    ):

        session.clear()

        session["authenticated"] = True

        return redirect(
            url_for("index")
        )


    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# PARSE RECIPIENTS API
# =========================================================

@app.post("/api/parse-recipients")
@login_required
def api_parse_recipients():

    data = request.get_json(
        silent=True
    ) or {}


    recipients, invalid = (
        parse_recipients(
            data.get(
                "recipients",
                ""
            )
        )
    )


    return jsonify({

        "count": len(
            recipients
        ),

        "recipients": recipients,

        "invalid": invalid[:20]

    })


# =========================================================
# SEND API
# =========================================================

@app.post("/api/send")
@login_required
def api_send():

    data = request.get_json(
        silent=True
    ) or {}


    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    sender_email = str(
        data.get(
            "sender_email",
            ""
        )
    ).strip()


    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).replace(
        " ",
        ""
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


    body = str(
        data.get(
            "body",
            ""
        )
    )


    raw_recipients = str(
        data.get(
            "recipients",
            ""
        )
    )


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400


    if not valid_email(
        sender_email
    ):

        return jsonify({
            "ok": False,
            "error": "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "ok": False,
            "error": "Gmail App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "ok": False,
            "error": "Email subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "ok": False,
            "error": "Message body is required."
        }), 400


    # =====================================================
    # RECIPIENTS
    # =====================================================

    recipients, invalid = (
        parse_recipients(
            raw_recipients
        )
    )


    if not recipients:

        return jsonify({
            "ok": False,
            "error": "No valid recipients were found."
        }), 400


    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "ok": False,
            "error": (
                f"Maximum "
                f"{MAX_RECIPIENTS} "
                f"recipients allowed."
            )
        }), 400


    # =====================================================
    # OPTIONAL TURNSTILE
    # =====================================================

    if (
        os.getenv(
            "TURNSTILE_SECRET_KEY"
        )
        and
        not turnstile_token
    ):

        return jsonify({
            "ok": False,
            "error": (
                "Spam protection "
                "verification is required."
            )
        }), 400


    # =====================================================
    # SEND
    # =====================================================

    sent = 0

    failed = []


    for index, recipient in enumerate(
        recipients
    ):

        try:

            personalized_body = (
                expand_spintax(
                    body
                )
            )


            personalized_subject = (
                expand_spintax(
                    subject
                )
            )


            # ---------------------------------------------
            # NAME PERSONALIZATION
            # ---------------------------------------------

            display_name = (
                recipient
                .split("@", 1)[0]
                .replace(".", " ")
                .replace("_", " ")
                .replace("-", " ")
                .title()
            )


            personalized_body = (
                personalized_body
                .replace(
                    "{name}",
                    display_name
                )
            )


            personalized_subject = (
                personalized_subject
                .replace(
                    "{name}",
                    display_name
                )
            )


            send_one(
                sender_name,
                sender_email,
                app_password,
                recipient,
                personalized_subject,
                personalized_body
            )


            sent += 1


        except Exception as error:

            failed.append({

                "email": recipient,

                "error": str(
                    error
                )[:180]

            })


        # Delay

        if index < len(
            recipients
        ) - 1:

            time.sleep(
                max(
                    0,
                    MIN_DELAY
                )
            )


    return jsonify({

        "ok": True,

        "total": len(
            recipients
        ),

        "sent": sent,

        "failed": len(
            failed
        ),

        "failures": failed,

        "invalid": invalid[:20]

    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        ),
        debug=(
            os.getenv(
                "FLASK_DEBUG",
                "0"
            ) == "1"
        )
    )
