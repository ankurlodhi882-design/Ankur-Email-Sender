import os
import re
import ssl
import smtplib
import secrets

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
    "change-this-secret"
)

LOGIN_USER = os.getenv("LOGIN_USER", "Ankur")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "Radhika")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))

MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(EMAIL_RE.fullmatch(email.strip()))


def parse_recipients(raw):
    values = re.split(r"[\s,;]+", raw or "")

    valid = []
    invalid = []
    seen = set()

    for value in values:
        email = value.strip()

        if not email:
            continue

        if not valid_email(email):
            invalid.append(email)
            continue

        key = email.lower()

        if key not in seen:
            seen.add(key)
            valid.append(email)

    return valid, invalid


def recipient_name(email):
    local = email.split("@", 1)[0]

    return (
        local
        .replace(".", " ")
        .replace("_", " ")
        .replace("-", " ")
        .title()
    )


def personalize(text, email):
    return text.replace(
        "{name}",
        recipient_name(email)
    )


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


@app.get("/login")
def login():

    if session.get("authenticated"):
        return redirect(url_for("index"))

    return render_template("login.html")


@app.post("/login")
def login_post():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    user_ok = secrets.compare_digest(
        username,
        LOGIN_USER
    )

    password_ok = secrets.compare_digest(
        password,
        LOGIN_PASSWORD
    )

    if user_ok and password_ok:

        session.clear()
        session["authenticated"] = True

        return redirect(url_for("index"))

    return render_template(
        "login.html",
        error="Invalid username or password."
    ), 401


@app.post("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


@app.post("/api/check")
@login_required
def check():

    data = request.get_json(
        silent=True
    ) or {}

    raw = str(
        data.get("recipients", "")
    )

    recipients, invalid = parse_recipients(raw)

    return jsonify({
        "ok": True,
        "count": len(recipients),
        "invalid": invalid[:50],
        "maximum": MAX_RECIPIENTS
    })


@app.post("/api/send")
@login_required
def send_api():

    data = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    sender_email = str(
        data.get("sender_email", "")
    ).strip()

    app_password = str(
        data.get("app_password", "")
    ).replace(" ", "").strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    text_body = str(
        data.get("body", "")
    ).strip()

    recipients_raw = str(
        data.get("recipients", "")
    )

    # -------------------------
    # Validation
    # -------------------------

    if not sender_name:
        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not valid_email(sender_email):
        return jsonify({
            "ok": False,
            "error": "Enter a valid sender email."
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

    if not text_body:
        return jsonify({
            "ok": False,
            "error": "Message is required."
        }), 400

    recipients, invalid = parse_recipients(
        recipients_raw
    )

    if not recipients:
        return jsonify({
            "ok": False,
            "error": "No valid recipients found."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "ok": False,
            "error": "Maximum 25 recipients are allowed."
        }), 400

    sent = 0
    failures = []

    context = ssl.create_default_context()

    try:

        # One SMTP connection for the entire batch.
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

            for recipient in recipients:

                try:

                    final_subject = personalize(
                        subject,
                        recipient
                    )

                    final_text = personalize(
                        text_body,
                        recipient
                    )

                    # Simple clean HTML version.
                    html_body = (
                        "<html><body>"
                        + "<div style="
                          "'font-family:Arial,sans-serif;"
                          "line-height:1.6'>"
                        + final_text
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\n", "<br>")
                        + "</div>"
                        + "</body></html>"
                    )

                    message = EmailMessage()

                    message["From"] = (
                        f"{sender_name} "
                        f"<{sender_email}>"
                    )

                    message["To"] = recipient

                    message["Subject"] = final_subject

                    message["Date"] = formatdate(
                        localtime=True
                    )

                    message["Message-ID"] = make_msgid()

                    # Plain-text alternative.
                    message.set_content(
                        final_text
                    )

                    # HTML alternative.
                    message.add_alternative(
                        html_body,
                        subtype="html"
                    )

                    smtp.send_message(
                        message
                    )

                    sent += 1

                except Exception as exc:

                    failures.append({
                        "email": recipient,
                        "error": str(exc)[:500]
                    })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP authentication failed. "
                "Use a Gmail App Password."
            ),
            "sent_before_error": sent
        }), 401

    except smtplib.SMTPException as exc:

        return jsonify({
            "ok": False,
            "error": (
                "SMTP error: "
                + str(exc)[:500]
            ),
            "sent_before_error": sent
        }), 502

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": (
                "Connection error: "
                + str(exc)[:500]
            ),
            "sent_before_error": sent
        }), 500

    return jsonify({
        "ok": True,
        "total": len(recipients),
        "sent": sent,
        "failed": len(failures),
        "invalid": invalid[:50],
        "failures": failures
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", "5000")
        ),
        debug=False
    )
