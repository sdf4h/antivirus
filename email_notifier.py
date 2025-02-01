import smtplib
from email.mime.text import MIMEText
from config import EMAIL_SETTINGS

def send_email(subject, body):
    """Отправка уведомления по email."""
    if not EMAIL_SETTINGS['email_to']:
        print("Email для уведомлений не указан. Пожалуйста, укажите email в настройках.")
        return

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SETTINGS['email_from']
    msg['To'] = EMAIL_SETTINGS['email_to']

    try:
        server = smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port'])
        server.starttls()
        server.login(EMAIL_SETTINGS['email_from'], EMAIL_SETTINGS['email_password'])
        server.sendmail(EMAIL_SETTINGS['email_from'], [EMAIL_SETTINGS['email_to']], msg.as_string())
        server.quit()
        print("Уведомление по email отправлено.")
    except Exception as e:
        print(f"Ошибка при отправке email: {e}")
