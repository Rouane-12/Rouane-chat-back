import requests
import os

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

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

    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json"
        },
        json={
            "sender": {"name": "Mon App", "email": SENDER_EMAIL},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": body
        }
    )

    if response.status_code not in [200, 201]:
        raise Exception(f"Brevo API error: {response.text}")