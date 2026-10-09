import os
import re
import ssl
import smtplib

from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify
)


# =========================================================
# FLASK
# =========================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)


# =========================================================
# DASHBOARD LOGIN
# =========================================================

LOGIN_USER = os.getenv(
    "LOGIN_USER",
    "Ankur"
)

LOGIN_PASSWORD = os.getenv(
    "LOGIN_PASSWORD",
    "Radhika"
)


# =========================================================
# GMAIL SMTP
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

# Gmail address stored in Vercel
SMTP_USERNAME = os.getenv(
    "SMTP_USERNAME",
    ""
)

# Gmail App Password stored in Vercel
SMTP_PASSWORD = os.getenv(
    "SMTP_PASSWORD",
    ""
)

MAX_RECIPIENTS = 25


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_REGEX = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(
        EMAIL_REGEX.match(
            email.strip()
        )
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(value):

    if not value:
        return []

    parts = re.split(
        r"[\s,;]+",
        str(value)
    )

    result = []
    seen = set()

    for item in parts:

        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

    return result


# =========================================================
# PERSONALIZATION
# =========================================================

def recipient_name(email):

    local = email.split(
        "@",
        1
    )[0]

    local = re.sub(
        r"[._-]+",
        " ",
        local
    )

    local = re.sub(
        r"\d+",
        "",
        local
    )

    local = " ".join(
        local.split()
    ).strip()

    if not local:
        return "there"

    return local.title()


def personalize(text, email):

    return text.replace(
        "{name}",
        recipient_name(email)
    )


# =========================================================
# LOGIN
# =========================================================

def logged_in():

    return session.get(
        "logged_in"
    ) is True


@app.route(
    "/",
    methods=["GET"]
)
def home():

    if not logged_in():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        if logged_in():

            return redirect(
                url_for("home")
            )

        return render_template(
            "login.html"
        )

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if (
        username == LOGIN_USER
        and password == LOGIN_PASSWORD
    ):

        session.clear()

        session["logged_in"] = True

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


@app.route(
    "/logout",
    methods=["GET", "POST"]
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HEALTH
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "ok": True,
        "service": "secure-mail-console",
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "sender_configured": bool(
            SMTP_USERNAME
        ),
        "password_configured": bool(
            SMTP_PASSWORD
        )
    })


# =========================================================
# SMTP CONFIG CHECK
# =========================================================

@app.route(
    "/api/smtp-status",
    methods=["GET"]
)
def smtp_status():

    if not logged_in():

        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    return jsonify({
        "ok": True,
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "sender_configured": bool(
            SMTP_USERNAME
        ),
        "password_configured": bool(
            SMTP_PASSWORD
        ),
        "sender": SMTP_USERNAME
        if SMTP_USERNAME
        else None
    })


# =========================================================
# CHECK RECIPIENTS
# =========================================================

@app.route(
    "/api/check",
    methods=["POST"]
)
def check_recipients():

    if not logged_in():

        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    recipients = parse_recipients(
        data.get(
            "recipients",
            ""
        )
    )

    if not recipients:

        return jsonify({
            "ok": False,
            "error": "No recipients provided."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "ok": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} "
                "recipients allowed."
            )
        }), 400

    valid = []
    invalid = []

    for email in recipients:

        if valid_email(email):

            valid.append(email)

        else:

            invalid.append(email)

    return jsonify({
        "ok": True,
        "count": len(valid),
        "valid": valid,
        "invalid": invalid
    })


# =========================================================
# TEST GMAIL SMTP
# =========================================================

@app.route(
    "/api/test-smtp",
    methods=["POST"]
)
def test_smtp():

    if not logged_in():

        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    if not SMTP_USERNAME:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP_USERNAME is missing "
                "in Vercel Environment Variables."
            )
        }), 500

    if not SMTP_PASSWORD:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP_PASSWORD is missing "
                "in Vercel Environment Variables."
            )
        }), 500

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            )

        return jsonify({
            "ok": True,
            "message": (
                "Gmail SMTP login successful."
            )
        })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail authentication failed. "
                "Check SMTP_USERNAME and "
                "SMTP_PASSWORD."
            )
        }), 401

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP connection failed: "
                + str(exc)
            )
        }), 500


# =========================================================
# SEND EMAIL
# =========================================================

@app.route(
    "/api/send",
    methods=["POST"]
)
def send_email():

    if not logged_in():

        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    # -----------------------------------------------------
    # ENVIRONMENT VARIABLES
    # -----------------------------------------------------

    if not SMTP_USERNAME:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP_USERNAME is not configured "
                "in Vercel Environment Variables."
            )
        }), 500

    if not SMTP_PASSWORD:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP_PASSWORD is not configured "
                "in Vercel Environment Variables."
            )
        }), 500

    # -----------------------------------------------------
    # REQUEST DATA
    # -----------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    sender_name = data.get(
        "sender_name",
        ""
    ).strip()

    subject = data.get(
        "subject",
        ""
    ).strip()

    body = data.get(
        "body",
        ""
    ).strip()

    raw_recipients = data.get(
        "recipients",
        ""
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not subject:

        return jsonify({
            "ok": False,
            "error": "Subject is required."
        }), 400

    if not body:

        return jsonify({
            "ok": False,
            "error": "Message is required."
        }), 400

    recipients = parse_recipients(
        raw_recipients
    )

    if not recipients:

        return jsonify({
            "ok": False,
            "error": "No recipients provided."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "ok": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} "
                "recipients allowed."
            )
        }), 400

    valid = []
    invalid = []

    for email in recipients:

        if valid_email(email):

            valid.append(email)

        else:

            invalid.append(email)

    if not valid:

        return jsonify({
            "ok": False,
            "error": "No valid recipients.",
            "invalid": invalid
        }), 400

    # -----------------------------------------------------
    # SEND
    # -----------------------------------------------------

    sent = 0
    failed = 0
    failures = []

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=30
        ) as smtp:

            # Login once
            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            )

            for recipient in valid:

                try:

                    personalized = personalize(
                        body,
                        recipient
                    )

                    message = EmailMessage()

                    message["From"] = formataddr(
                        (
                            sender_name,
                            SMTP_USERNAME
                        )
                    )

                    message["To"] = recipient

                    message["Subject"] = subject

                    message["Date"] = formatdate(
                        localtime=True
                    )

                    message["Message-ID"] = (
                        make_msgid()
                    )

                    # Plain-text message
                    message.set_content(
                        personalized
                    )

                    # Simple HTML alternative
                    html = (
                        personalized
                        .replace(
                            "&",
                            "&amp;"
                        )
                        .replace(
                            "<",
                            "&lt;"
                        )
                        .replace(
                            ">",
                            "&gt;"
                        )
                        .replace(
                            "\n",
                            "<br>"
                        )
                    )

                    message.add_alternative(
                        f"""
<html>
<body>
<p>{html}</p>
</body>
</html>
""",
                        subtype="html"
                    )

                    smtp.send_message(
                        message
                    )

                    sent += 1

                except Exception as exc:

                    failed += 1

                    failures.append({
                        "email": recipient,
                        "error": str(exc)
                    })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail SMTP authentication failed. "
                "Check your Vercel SMTP_USERNAME "
                "and SMTP_PASSWORD."
            )
        }), 401

    except smtplib.SMTPConnectError as exc:

        return jsonify({
            "ok": False,
            "error": (
                "Could not connect to Gmail SMTP: "
                + str(exc)
            )
        }), 502

    except smtplib.SMTPServerDisconnected as exc:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail SMTP disconnected: "
                + str(exc)
            )
        }), 502

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP error: "
                + str(exc)
            )
        }), 500

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return jsonify({
        "ok": True,
        "sent": sent,
        "failed": failed,
        "invalid": invalid,
        "failures": failures,
        "status": (
            "accepted_by_smtp"
            if sent > 0
            else "not_accepted"
        ),
        "message": (
            f"{sent} email(s) accepted by Gmail SMTP."
            if sent > 0
            else "No email was accepted by SMTP."
        )
    })


# =========================================================
# LOCAL RUN
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
