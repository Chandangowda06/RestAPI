from smtplib import SMTPException
import smtplib
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.urls import reverse
from leavemanagement import settings
from user_app.models import User


def generate_password_reset_token(user):
    try:
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        return uidb64, token
    except Exception as e:
        print(e)

def send_password_reset_email(user, request):
    try:
        uidb64, token = generate_password_reset_token(user)
        domain = request.headers.get('Origin')
        reset_url =  f"{domain}/password_reset/confirm/{uidb64}/{token}/"
        message = f"Click the link to reset your password: {reset_url}"
        send_email('Password reset request', message, user.email)
    except Exception as e:
        print(e)


def extract_user_from_token(uidb64, token):
    try:
        user_id = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=user_id)
        if default_token_generator.check_token(user, token):
            return user
    except (ValueError, User.DoesNotExist):
        pass
    return None

def send_email(sub, msg, to):
    try:
        send_mail(
        subject=sub,
        message=msg,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list = [to],
        fail_silently=False,
        )
    except (SMTPException, smtplib.SMTPException) as e:
        raise("Error in sending email")

