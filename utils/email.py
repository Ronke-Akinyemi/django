from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from decouple import config
import os


class SendMail:

    @staticmethod
    def send_email(data, html=None):
        send_email = EmailMessage(
            subject=data["subject"], body=data["body"], from_email=settings.EMAIL_FROM_USER, to=[data["user"]])
        if html:
            send_email.content_subtype = 'html'
        try:
            send_email.send()
        except BaseException:
            pass

    @staticmethod
    def send_invite_mail(info):
        data = {}
        data["subject"] = "Admin Invitation"
        data["body"] = f'Your Login details is\n\nEmail: {info["email"]}\nPassowrd: {info["password"]}'
        data["user"] = info["email"]
        SendMail.send_email(data)

    @staticmethod
    def send_welcome_mail(data):
        SendMail.send_email(data)

    @staticmethod
    def send_loan_notification_email(info):
        frontend_url = config("FRONTEND_URL")
        html_content = render_to_string('mail.html', {
            "frontend_url":frontend_url,
            })
        data = {
            "subject": "",
            "body": html_content,
            "user": info["email"]
        }
        SendMail.send_email(data, html=True)

        # SendMail.send_email(data, html=True)

    @staticmethod
    def send_email_verification_mail(info):
        data = {}
        data["subject"] = "Email verification"
        message = f"Dear {info['firstname']} {info['lastname']}\n\nYour Verification code is {info['token']}"
        data["body"] = message
        data["user"] = info["user"]
        SendMail.send_email(data)

    @staticmethod
    def send_password_reset_mail(info):
        data = {}
        message = f"Please use the this code to reset your password {info['token']}"
        data['body'] = message
        data["user"] = info["email"]
        data["subject"] = "Reset password email"
        SendMail.send_email(data)

