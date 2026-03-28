import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_USER = "97563a001@smtp-brevo.com"
SMTP_PASSWORD = "xsmtpsib-4477363cec6f1b44502c04a33e107c0e7e81be212dc25127b0a278debd30eb4a-xtKO2TiR5ARg2ctf"
SENDER_EMAIL = "Mon App <djossouvirouane6@gmail.com>"

def send_otp_email(to_email: str, otp_code: str, purpose: str):
    subject = "Code de vérification" if purpose == "register" else "Réinitialisation de mot de passe"
    title = "Vérifiez votre compte" if purpose == "register" else "Réinitialisation du mot de passe"

    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #0a0a0a; color: #fff; padding: 40px;">
        <div style="max-width: 480px; margin: 0 auto; background: #111; border: 1px solid #222; border-radius: 12px; padding: 40px;">
            <h1 style="color: #4ade80; margin-bottom: 8px; font-size: 24px;">{title}</h1>
            <p style="color: #aaa; margin-bottom: 32px;">Votre code OTP valable 10 minutes :</p>
            <div style="background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 24px; text-align: center;">
                <span style="font-size: 40px; font-weight: 700; letter-spacing: 12px; color: #4ade80;">{otp_code}</span>
            </div>
            <p style="color: #555; margin-top: 32px; font-size: 13px;">Si vous n'avez pas fait cette demande, ignorez cet email.</p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail("djossouvirouane6@gmail.com", to_email, msg.as_string())