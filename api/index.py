import os
import re
import ssl
import smtplib
import secrets
import random

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


# ==========================================================
# FLASK APP
# ==========================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
    static_url_path="/static",
)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-to-a-long-random-secret",
)


# ==========================================================
# LOGIN
# ==========================================================

LOGIN_USER = "Ankur"
LOGIN_PASSWORD = "Radhika"


# ==========================================================
# SMTP
# ==========================================================

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "465",
    )
)

MAX_RECIPIENTS = int(
    os.getenv(
        "MAX_RECIPIENTS",
        "25",
    )
)


# ==========================================================
# EMAIL VALIDATION
# ==========================================================

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(
        EMAIL_RE.fullmatch(
            email.strip()
        )
    )


# ==========================================================
# LOGIN REQUIRED
# ==========================================================

def login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get(
            "authenticated"
        ):
            return redirect(
                url_for("login")
            )

        return func(
            *args,
            **kwargs
        )

    return wrapper


# ==========================================================
# RECIPIENT PARSER
# ==========================================================

def parse_recipients(raw):

    parts = re.split(
        r"[\s,;]+",
        raw or "",
    )

    recipients = []
    invalid = []
    seen = set()

    for value in parts:

        email = value.strip()

        if not email:
            continue

        if valid_email(email):

            key = email.lower()

            if key not in seen:

                seen.add(key)
                recipients.append(email)

        else:

            invalid.append(email)

    return recipients, invalid


# ==========================================================
# SPINTAX
#
# Example:
# {Hi|Hello} {name}
# ==========================================================

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


# ==========================================================
# NAME FROM EMAIL
# ==========================================================

def name_from_email(email):

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


# ==========================================================
# SEND ONE EMAIL
# ==========================================================

def send_one_email(
    sender_name,
    sender_email,
    app_password,
    recipient,
    subject,
    body,
    reply_to="",
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

    if (
        reply_to
        and valid_email(reply_to)
    ):
        message["Reply-To"] = reply_to

    message.set_content(
        body.strip()
    )

    context = (
        ssl.create_default_context()
    )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=30,
    ) as smtp:

        smtp.login(
            sender_email,
            app_password,
        )

        smtp.send_message(
            message
        )


# ==========================================================
# HOME
# ==========================================================

@app.get("/")
@login_required
def index():

    return render_template(
        "index.html"
    )


# ==========================================================
# LOGIN
# ==========================================================

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
def do_login():

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

    if (
        secrets.compare_digest(
            username,
            LOGIN_USER,
        )
        and
        secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        )
    ):

        session.clear()

        session["authenticated"] = True

        return redirect(
            url_for("index")
        )

    return render_template(
        "login.html",
        error="Invalid username or password.",
    ), 401


# ==========================================================
# LOGOUT
# ==========================================================

@app.post("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================================
# PARSE RECIPIENTS API
# ==========================================================

@app.post("/api/parse-recipients")
@login_required
def parse_api():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    recipients, invalid = (
        parse_recipients(
            data.get(
                "recipients",
                ""
            )
        )
    )

    return jsonify({

        "ok": True,

        "count": len(
            recipients
        ),

        "recipients": recipients,

        "invalid": invalid[:30],

    })


# ==========================================================
# SEND EMAIL API
# ==========================================================

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

    reply_to = str(
        data.get(
            "reply_to",
            ""
        )
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


    # ------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------

    if not sender_name:

        return jsonify({
            "ok": False,
            "error": "Sender name is required.",
        }), 400


    if not valid_email(
        sender_email
    ):

        return jsonify({
            "ok": False,
            "error": "Enter a valid sender Gmail address.",
        }), 400


    if not app_password:

        return jsonify({
            "ok": False,
            "error": "Gmail App Password is required.",
        }), 400


    if not subject:

        return jsonify({
            "ok": False,
            "error": "Email subject is required.",
        }), 400


    if not body.strip():

        return jsonify({
            "ok": False,
            "error": "Message body is required.",
        }), 400


    recipients, invalid = (
        parse_recipients(
            raw_recipients
        )
    )


    if not recipients:

        return jsonify({
            "ok": False,
            "error": "No valid recipients found.",
        }), 400


    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "ok": False,
            "error": (
                f"Maximum "
                f"{MAX_RECIPIENTS} "
                f"recipients per request."
            ),
        }), 400


    # ------------------------------------------------------
    # SEND
    # ------------------------------------------------------

    sent = 0
    failed = []

    for recipient in recipients:

        try:

            recipient_name = (
                name_from_email(
                    recipient
                )
            )

            final_subject = (
                expand_spintax(
                    subject
                )
                .replace(
                    "{name}",
                    recipient_name
                )
            )

            final_body = (
                expand_spintax(
                    body
                )
                .replace(
                    "{name}",
                    recipient_name
                )
            )

            send_one_email(
                sender_name,
                sender_email,
                app_password,
                recipient,
                final_subject,
                final_body,
                reply_to,
            )

            sent += 1

        except Exception as error:

            failed.append({

                "email": recipient,

                "error": str(
                    error
                )[:250],

            })


    return jsonify({

        "ok": True,

        "total": len(
            recipients
        ),

        "sent": sent,

        "failed": len(
            failed
        ),

        "remaining": 0,

        "invalid": invalid[:30],

        "failures": failed,

    })


# ==========================================================
# RUN
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        ),
        debug=False,
    )
