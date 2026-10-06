import os
import re
import ssl
import smtplib
import secrets
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from flask import Flask, render_template, request, jsonify, redirect, url_for, session

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-secret-key")

LOGIN_USER = os.getenv("LOGIN_USER", "Ankur")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "Radhika")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))

MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def parse_recipients(raw_text):
    if not raw_text:
        return []

    parts = re.split(r"[\s,;]+", raw_text.strip())

    recipients = []
    seen = set()

    for item in parts:
        email = item.strip().lower()

        if not email:
            continue

        if email not in seen:
            seen.add(email)
            recipients.append(email)

    return recipients


def valid_email(email):
    return bool(email and EMAIL_RE.match(email))


def display_name_from_email(email):
    local = email.split("@", 1)[0]
    local = re.sub(r"[._-]+", " ", local)
    return local.strip().title() or "there"


def render_personalized(text, recipient):
    return text.replace("{name}", display_name_from_email(recipient))


def create_message(sender_name, sender_email, recipient, subject, body):
    personalized_body = render_personalized(body, recipient)

    msg = EmailMessage()

    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    msg.set_content(personalized_body)

    html_body = (
        personalized_body
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br>")
    )

    msg.add_alternative(
        f"""
        <!doctype html>
        <html>
        <body style="font-family:Arial,sans-serif;line-height:1.6;">
            {html_body}
        </body>
        </html>
        """,
        subtype="html",
    )

    return msg


def smtp_connection(sender_email, app_password):
    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=30,
    )

    server.login(sender_email, app_password)

    return server


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if (
            secrets.compare_digest(username, LOGIN_USER)
            and secrets.compare_digest(password, LOGIN_PASSWORD)
        ):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password.",
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "secure-mail-console",
            "time": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.route("/api/check", methods=["POST"])
def check_recipients():
    if not session.get("logged_in"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    raw_recipients = data.get("recipients", "")
    recipients = parse_recipients(raw_recipients)

    if not recipients:
        return jsonify(
            {
                "ok": False,
                "error": "No recipients found.",
            }
        ), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(
            {
                "ok": False,
                "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed.",
                "count": len(recipients),
            }
        ), 400

    invalid = [x for x in recipients if not valid_email(x)]

    return jsonify(
        {
            "ok": len(invalid) == 0,
            "count": len(recipients),
            "valid": [x for x in recipients if valid_email(x)],
            "invalid": invalid,
        }
    )


@app.route("/api/test-smtp", methods=["POST"])
def test_smtp():
    if not session.get("logged_in"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    sender_email = data.get("sender_email", "").strip()
    app_password = data.get("app_password", "").strip()

    if not valid_email(sender_email):
        return jsonify(
            {
                "ok": False,
                "error": "Enter a valid Gmail address.",
            }
        ), 400

    if not app_password:
        return jsonify(
            {
                "ok": False,
                "error": "Enter your Gmail App Password.",
            }
        ), 400

    server = None

    try:
        server = smtp_connection(sender_email, app_password)

        return jsonify(
            {
                "ok": True,
                "message": "SMTP login successful.",
            }
        )

    except smtplib.SMTPAuthenticationError:
        return jsonify(
            {
                "ok": False,
                "error": (
                    "Gmail authentication failed. "
                    "Use a Gmail App Password and verify 2-Step Verification."
                ),
            }
        ), 400

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": f"SMTP connection failed: {str(exc)}",
            }
        ), 400

    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


@app.route("/api/send", methods=["POST"])
def send_mail():
    if not session.get("logged_in"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    sender_name = data.get("sender_name", "").strip()
    sender_email = data.get("sender_email", "").strip()
    app_password = data.get("app_password", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")
    raw_recipients = data.get("recipients", "")

    if not sender_name:
        return jsonify(
            {"ok": False, "error": "Sender name is required."}
        ), 400

    if not valid_email(sender_email):
        return jsonify(
            {"ok": False, "error": "Enter a valid sender email."}
        ), 400

    if not app_password:
        return jsonify(
            {"ok": False, "error": "Gmail App Password is required."}
        ), 400

    if not subject:
        return jsonify(
            {"ok": False, "error": "Subject is required."}
        ), 400

    if not body.strip():
        return jsonify(
            {"ok": False, "error": "Message body is required."}
        ), 400

    recipients = parse_recipients(raw_recipients)

    if not recipients:
        return jsonify(
            {"ok": False, "error": "No recipients found."}
        ), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(
            {
                "ok": False,
                "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed.",
            }
        ), 400

    invalid = [email for email in recipients if not valid_email(email)]

    if invalid:
        return jsonify(
            {
                "ok": False,
                "error": "Some recipient addresses are invalid.",
                "invalid": invalid,
            }
        ), 400

    sent_items = []
    failed_items = []

    server = None

    try:
        server = smtp_connection(sender_email, app_password)

        for recipient in recipients:
            try:
                msg = create_message(
                    sender_name=sender_name,
                    sender_email=sender_email,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                )

                refused = server.send_message(msg)

                if refused:
                    failed_items.append(
                        {
                            "email": recipient,
                            "error": str(refused),
                        }
                    )
                else:
                    sent_items.append(
                        {
                            "email": recipient,
                            "status": "accepted_by_smtp",
                        }
                    )

            except Exception as exc:
                failed_items.append(
                    {
                        "email": recipient,
                        "error": str(exc),
                    }
                )

        return jsonify(
            {
                "ok": len(sent_items) > 0 and len(failed_items) == 0,
                "partial": len(sent_items) > 0 and len(failed_items) > 0,
                "total": len(recipients),
                "sent": len(sent_items),
                "failed": len(failed_items),
                "sent_items": sent_items,
                "failed_items": failed_items,
                "note": (
                    "accepted_by_smtp means the SMTP server accepted the "
                    "message. It does not guarantee Inbox placement."
                ),
            }
        )

    except smtplib.SMTPAuthenticationError:
        return jsonify(
            {
                "ok": False,
                "error": (
                    "Gmail authentication failed. "
                    "Use the Gmail App Password, not your normal Gmail password."
                ),
            }
        ), 400

    except smtplib.SMTPException as exc:
        return jsonify(
            {
                "ok": False,
                "error": f"SMTP error: {str(exc)}",
            }
        ), 400

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": f"Sending failed: {str(exc)}",
            }
        ), 500

    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
