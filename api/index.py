import os
import re
import ssl
import smtplib
import secrets
import time

from functools import wraps
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
)


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
    static_url_path="/static",
)

# =========================================================
# CONFIG
# =========================================================

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-in-vercel"
)

LOGIN_USER = os.getenv(
    "LOGIN_USER",
    "Ankur"
)

LOGIN_PASSWORD = os.getenv(
    "LOGIN_PASSWORD",
    "Radhika"
)

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

MAX_RECIPIENTS = 25

# Small delay between messages.
# This is not a spam-bypass mechanism; it simply avoids
# hammering the SMTP connection.
SEND_DELAY = float(
    os.getenv(
        "SEND_DELAY",
        "1"
    )
)

EMAIL_REGEX = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# HELPERS
# =========================================================

def valid_email(email):
    return bool(
        EMAIL_REGEX.fullmatch(
            email.strip()
        )
    )


def login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get(
            "authenticated",
            False
        ):
            return redirect(
                url_for("login")
            )

        return func(
            *args,
            **kwargs
        )

    return wrapper


def parse_recipients(raw):

    values = re.split(
        r"[\s,;]+",
        raw or ""
    )

    valid = []
    invalid = []
    seen = set()

    for value in values:

        email = value.strip()

        if not email:
            continue

        if valid_email(email):

            key = email.lower()

            if key not in seen:

                seen.add(key)
                valid.append(email)

        else:

            invalid.append(email)

    return valid, invalid


def recipient_name(email):

    local = email.split(
        "@",
        1
    )[0]

    name = (
        local
        .replace(".", " ")
        .replace("_", " ")
        .replace("-", " ")
    )

    return name.title()


def personalize(text, email):

    name = recipient_name(email)

    return text.replace(
        "{name}",
        name
    )


# =========================================================
# SEND EMAIL
# =========================================================

def send_email(
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

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message.set_content(
        body.strip()
    )

    context = ssl.create_default_context()

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


@app.post("/login")
def login_post():

    username = (
        request.form
        .get(
            "username",
            ""
        )
        .strip()
    )

    password = request.form.get(
        "password",
        ""
    )

    correct_user = secrets.compare_digest(
        username,
        LOGIN_USER
    )

    correct_password = secrets.compare_digest(
        password,
        LOGIN_PASSWORD
    )

    if correct_user and correct_password:

        session.clear()

        session["authenticated"] = True

        return redirect(
            url_for("index")
        )

    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


@app.post("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/")
@login_required
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# RECIPIENT CHECK
# =========================================================

@app.post("/api/check")
@login_required
def check_recipients():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    raw = str(
        data.get(
            "recipients",
            ""
        )
    )

    recipients, invalid = parse_recipients(
        raw
    )

    return jsonify({
        "ok": True,
        "count": len(recipients),
        "invalid": invalid[:50],
        "maximum": MAX_RECIPIENTS
    })


# =========================================================
# SEND
# =========================================================

@app.post("/api/send")
@login_required
def send_api():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

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

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not valid_email(sender_email):

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
            "error": "Subject is required."
        }), 400

    if not body.strip():

        return jsonify({
            "ok": False,
            "error": "Message is required."
        }), 400

    recipients, invalid = parse_recipients(
        raw_recipients
    )

    if not recipients:

        return jsonify({
            "ok": False,
            "error": "No valid recipients found."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "ok": False,
            "error": (
                "Maximum 25 recipients "
                "are allowed."
            ),
            "count": len(recipients)
        }), 400

    # -----------------------------------------------------
    # SEND EACH MESSAGE INDIVIDUALLY
    # -----------------------------------------------------

    total = len(recipients)

    sent = 0

    failed = []

    for index, recipient in enumerate(
        recipients
    ):

        try:

            final_subject = personalize(
                subject,
                recipient
            )

            final_body = personalize(
                body,
                recipient
            )

            send_email(
                sender_name,
                sender_email,
                app_password,
                recipient,
                final_subject,
                final_body
            )

            sent += 1

        except Exception as exc:

            failed.append({
                "email": recipient,
                "error": str(exc)[:300]
            })

        # Small delay between messages.
        if index < total - 1:

            time.sleep(
                SEND_DELAY
            )

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return jsonify({
        "ok": True,
        "total": total,
        "sent": sent,
        "failed": len(failed),
        "remaining": 0,
        "invalid": invalid[:50],
        "failures": failed
    })


# =========================================================
# LOCAL SERVER
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
        debug=False
    )
