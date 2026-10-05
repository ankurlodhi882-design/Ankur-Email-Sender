import os
import re
import ssl
import smtplib
import secrets
import html

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

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "replace-this-with-a-long-random-secret",
)


# ---------------------------------------------------------
# Login
# ---------------------------------------------------------

LOGIN_USER = os.getenv("LOGIN_USER", "Ankur")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "Radhika")


# ---------------------------------------------------------
# SMTP
# ---------------------------------------------------------

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

SMTP_PORT = int(
    os.getenv("SMTP_PORT", "465")
)

MAX_RECIPIENTS = 25


# ---------------------------------------------------------
# Email validation
# ---------------------------------------------------------

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def is_valid_email(email):
    return bool(
        EMAIL_PATTERN.fullmatch(
            email.strip()
        )
    )


def parse_recipients(raw):
    """
    Accept:
      email1@example.com
      email2@example.com

    or comma/semicolon/space separated addresses.
    """

    parts = re.split(
        r"[\s,;]+",
        raw or ""
    )

    valid = []
    invalid = []
    seen = set()

    for item in parts:
        email = item.strip()

        if not email:
            continue

        if not is_valid_email(email):
            invalid.append(email)
            continue

        key = email.lower()

        if key not in seen:
            seen.add(key)
            valid.append(email)

    return valid, invalid


# ---------------------------------------------------------
# Personalization
# ---------------------------------------------------------

def get_recipient_name(email):
    local_part = email.split(
        "@",
        1
    )[0]

    return (
        local_part
        .replace(".", " ")
        .replace("_", " ")
        .replace("-", " ")
        .title()
    )


def personalize(text, recipient):
    return text.replace(
        "{name}",
        get_recipient_name(recipient)
    )


# ---------------------------------------------------------
# Authentication
# ---------------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):
            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# ---------------------------------------------------------
# Login routes
# ---------------------------------------------------------

@app.get("/login")
def login():

    if session.get("authenticated"):
        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


@app.post("/login")
def login_submit():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    username_ok = secrets.compare_digest(
        username,
        LOGIN_USER
    )

    password_ok = secrets.compare_digest(
        password,
        LOGIN_PASSWORD
    )

    if username_ok and password_ok:

        session.clear()

        session["authenticated"] = True

        return redirect(
            url_for("dashboard")
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


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

@app.get("/")
@login_required
def dashboard():

    return render_template(
        "index.html"
    )


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console",
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "max_recipients": MAX_RECIPIENTS,
    })


# ---------------------------------------------------------
# Recipient checker
# ---------------------------------------------------------

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

    valid, invalid = parse_recipients(
        raw
    )

    return jsonify({
        "ok": True,
        "valid_count": len(valid),
        "invalid_count": len(invalid),
        "valid": valid,
        "invalid": invalid[:50],
        "maximum": MAX_RECIPIENTS,
    })


# ---------------------------------------------------------
# SMTP test
# ---------------------------------------------------------

@app.post("/api/test-smtp")
@login_required
def test_smtp():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

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
    ).replace(" ", "").strip()

    if not is_valid_email(
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

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=30,
        ) as smtp:

            smtp.ehlo()

            smtp.login(
                sender_email,
                app_password
            )

        return jsonify({
            "ok": True,
            "message": (
                "SMTP connection and authentication "
                "were successful."
            ),
        })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail authentication failed. "
                "Use a valid Gmail App Password."
            ),
        }), 401

    except smtplib.SMTPException as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP error: "
                + str(exc)[:500]
            ),
        }), 502

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": (
                "Connection error: "
                + str(exc)[:500]
            ),
        }), 500


# ---------------------------------------------------------
# Send mail
# ---------------------------------------------------------

@app.post("/api/send")
@login_required
def send_email():

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
    ).replace(" ", "").strip()

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
    ).strip()

    raw_recipients = str(
        data.get(
            "recipients",
            ""
        )
    )

    # -----------------------------
    # Validation
    # -----------------------------

    if not sender_name:
        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not is_valid_email(
        sender_email
    ):
        return jsonify({
            "ok": False,
            "error": "Invalid sender email."
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
                "Maximum 25 recipients are allowed."
            ),
        }), 400

    sent = []
    failed = []

    context = ssl.create_default_context()

    # -----------------------------
    # SMTP connection
    # -----------------------------

    try:

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=30,
        ) as smtp:

            smtp.ehlo()

            smtp.login(
                sender_email,
                app_password
            )

            # -------------------------
            # Individual messages
            # -------------------------

            for recipient in recipients:

                try:

                    final_subject = personalize(
                        subject,
                        recipient
                    )

                    final_body = personalize(
                        body,
                        recipient
                    )

                    escaped_body = html.escape(
                        final_body
                    )

                    html_body = (
                        "<!doctype html>"
                        "<html>"
                        "<body>"
                        "<div style="
                        "'font-family:Arial,"
                        "Helvetica,sans-serif;"
                        "line-height:1.6;"
                        "white-space:normal;'>"
                        + escaped_body.replace(
                            "\n",
                            "<br>"
                        )
                        + "</div>"
                        "</body>"
                        "</html>"
                    )

                    message = EmailMessage()

                    message["From"] = (
                        f"{sender_name} "
                        f"<{sender_email}>"
                    )

                    message["To"] = recipient

                    message["Subject"] = (
                        final_subject
                    )

                    message["Date"] = formatdate(
                        localtime=True
                    )

                    message["Message-ID"] = (
                        make_msgid()
                    )

                    message.set_content(
                        final_body
                    )

                    message.add_alternative(
                        html_body,
                        subtype="html"
                    )

                    smtp.send_message(
                        message
                    )

                    sent.append({
                        "email": recipient,
                        "status": "accepted_by_smtp"
                    })

                except Exception as exc:

                    failed.append({
                        "email": recipient,
                        "error": str(exc)[:500]
                    })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail authentication failed. "
                "Check the Gmail address and "
                "App Password."
            ),
            "sent_before_error": len(sent),
            "failed_before_error": len(failed),
        }), 401

    except smtplib.SMTPException as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP error: "
                + str(exc)[:500]
            ),
            "sent_before_error": len(sent),
            "failed_before_error": len(failed),
        }), 502

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP connection error: "
                + str(exc)[:500]
            ),
            "sent_before_error": len(sent),
            "failed_before_error": len(failed),
        }), 500

    return jsonify({
        "ok": True,
        "total": len(recipients),
        "sent": len(sent),
        "failed": len(failed),
        "invalid": invalid[:50],
        "sent_items": sent,
        "failed_items": failed,
        "delivery_note": (
            "accepted_by_smtp means the SMTP server "
            "accepted the message for processing. "
            "It does not guarantee Inbox placement."
        ),
    })


# ---------------------------------------------------------
# Local development
# ---------------------------------------------------------

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
