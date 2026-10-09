import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from flask import Flask, request, jsonify, render_template, redirect, url_for, session


# =========================================================
# APP CONFIG
# =========================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    os.getenv(
        "FLASK_SECRET_KEY",
        "change-this-session-secret-in-vercel"
    )
)


# =========================================================
# LOGIN CONFIG
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
# SMTP CONFIG
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

MAX_RECIPIENTS = 25


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def is_valid_email(email):
    return bool(
        EMAIL_PATTERN.match(
            email.strip()
        )
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(value):
    """
    Accepts:
      email1@example.com
      email2@example.com

    Also supports:
      comma
      semicolon
      spaces
      new lines
    """

    if not value:
        return []

    emails = re.split(
        r"[\s,;]+",
        str(value)
    )

    cleaned = []

    for email in emails:

        email = email.strip()

        if not email:
            continue

        email_lower = email.lower()

        if email_lower not in cleaned:
            cleaned.append(email_lower)

    return cleaned


# =========================================================
# PERSONALIZATION
# =========================================================

def get_recipient_name(email):
    """
    Example:

    john.smith@gmail.com
    -> John Smith

    john@gmail.com
    -> John
    """

    local_part = email.split(
        "@",
        1
    )[0]

    local_part = re.sub(
        r"[._-]+",
        " ",
        local_part
    )

    local_part = re.sub(
        r"\d+",
        "",
        local_part
    )

    local_part = " ".join(
        local_part.split()
    ).strip()

    if not local_part:
        return "there"

    return local_part.title()


def personalize_message(
    message,
    recipient_email
):

    name = get_recipient_name(
        recipient_email
    )

    return message.replace(
        "{name}",
        name
    )


# =========================================================
# LOGIN CHECK
# =========================================================

def login_required():
    return session.get(
        "logged_in"
    ) is True


# =========================================================
# HOME / LOGIN
# =========================================================

@app.route(
    "/",
    methods=["GET"]
)
def index():

    if not login_required():
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

        if login_required():
            return redirect(
                url_for("index")
            )

        return render_template(
            "login.html"
        )

    username = (
        request.form.get(
            "username",
            ""
        ).strip()
    )

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
            url_for("index")
        )

    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["POST", "GET"]
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HEALTH CHECK
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
        "max_recipients": MAX_RECIPIENTS
    })


# =========================================================
# RECIPIENT CHECK
# =========================================================

@app.route(
    "/api/check",
    methods=["POST"]
)
def check_recipients():

    if not login_required():

        return jsonify({
            "ok": False,
            "error": "Unauthorized."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    raw_recipients = data.get(
        "recipients",
        ""
    )

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
                "recipients are allowed."
            )
        }), 400

    valid = []
    invalid = []

    for email in recipients:

        if is_valid_email(email):
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
# SMTP LOGIN TEST
# =========================================================

@app.route(
    "/api/test-smtp",
    methods=["POST"]
)
def test_smtp():

    if not login_required():

        return jsonify({
            "ok": False,
            "error": "Unauthorized."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    sender_email = (
        data.get(
            "sender_email",
            ""
        ).strip()
    )

    app_password = (
        data.get(
            "app_password",
            ""
        ).strip()
    )

    if not sender_email:

        return jsonify({
            "ok": False,
            "error": "Gmail address is required."
        }), 400

    if not is_valid_email(
        sender_email
    ):

        return jsonify({
            "ok": False,
            "error": "Invalid Gmail address."
        }), 400

    if not app_password:

        return jsonify({
            "ok": False,
            "error": "Gmail App Password is required."
        }), 400

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=20
        ) as smtp:

            smtp.login(
                sender_email,
                app_password
            )

        return jsonify({
            "ok": True,
            "message": (
                "SMTP authentication successful."
            )
        })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail SMTP authentication failed. "
                "Use a valid Gmail App Password."
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
# SEND EMAILS
# =========================================================

@app.route(
    "/api/send",
    methods=["POST"]
)
def send_emails():

    if not login_required():

        return jsonify({
            "ok": False,
            "error": "Unauthorized."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    # -----------------------------------------------------
    # INPUTS
    # -----------------------------------------------------

    sender_name = (
        data.get(
            "sender_name",
            ""
        ).strip()
    )

    sender_email = (
        data.get(
            "sender_email",
            ""
        ).strip()
    )

    app_password = (
        data.get(
            "app_password",
            ""
        ).strip()
    )

    subject = (
        data.get(
            "subject",
            ""
        ).strip()
    )

    body = (
        data.get(
            "body",
            ""
        ).strip()
    )

    raw_recipients = data.get(
        "recipients",
        ""
    )

    # -----------------------------------------------------
    # REQUIRED FIELD VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not sender_email:

        return jsonify({
            "ok": False,
            "error": "Sender Gmail address is required."
        }), 400

    if not is_valid_email(
        sender_email
    ):

        return jsonify({
            "ok": False,
            "error": "Invalid sender email address."
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

    if not body:

        return jsonify({
            "ok": False,
            "error": "Message body is required."
        }), 400

    # -----------------------------------------------------
    # RECIPIENTS
    # -----------------------------------------------------

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
                "recipients are allowed."
            )
        }), 400

    valid_recipients = []
    invalid_recipients = []

    for email in recipients:

        if is_valid_email(email):

            valid_recipients.append(
                email
            )

        else:

            invalid_recipients.append(
                email
            )

    if not valid_recipients:

        return jsonify({
            "ok": False,
            "error": "No valid recipients found.",
            "invalid": invalid_recipients
        }), 400

    # -----------------------------------------------------
    # SMTP CONNECTION
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

            # ---------------------------------------------
            # LOGIN ONCE
            # ---------------------------------------------

            smtp.login(
                sender_email,
                app_password
            )

            # ---------------------------------------------
            # SEND ONE MESSAGE PER RECIPIENT
            # ---------------------------------------------

            for recipient in valid_recipients:

                try:

                    personalized_body = (
                        personalize_message(
                            body,
                            recipient
                        )
                    )

                    message = EmailMessage()

                    message["From"] = formataddr(
                        (
                            sender_name,
                            sender_email
                        )
                    )

                    message["To"] = recipient

                    message["Subject"] = subject

                    message["Date"] = (
                        __import__(
                            "email.utils",
                            fromlist=["formatdate"]
                        ).formatdate(
                            localtime=True
                        )
                    )

                    message["Message-ID"] = (
                        make_msgid()
                    )

                    # -------------------------------------
                    # PLAIN TEXT
                    # -------------------------------------

                    message.set_content(
                        personalized_body
                    )

                    # -------------------------------------
                    # SIMPLE HTML ALTERNATIVE
                    # -------------------------------------

                    html_body = (
                        personalized_body
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
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
</head>
<body>
<p>{html_body}</p>
</body>
</html>
""",
                        subtype="html"
                    )

                    # -------------------------------------
                    # SMTP HANDOFF
                    # -------------------------------------

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
                "Check the Gmail address and App Password."
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
                "SMTP sending error: "
                + str(exc)
            )
        }), 500

    # =====================================================
    # RESPONSE
    # =====================================================

    return jsonify({
        "ok": True,

        "sent": sent,

        "failed": failed,

        "invalid": invalid_recipients,

        "failures": failures,

        "total_valid": len(
            valid_recipients
        ),

        "status": (
            "accepted_by_smtp"
            if sent > 0
            else "not_accepted"
        ),

        "message": (
            f"{sent} message(s) were accepted "
            "by the SMTP server."
            if sent > 0
            else "No message was accepted by SMTP."
        )
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
        debug=False
    )
