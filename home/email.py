from django.core.mail import send_mail
import random
from django.conf import settings
from .models import CustomUser
from django.core.exceptions import ObjectDoesNotExist


def send_otp_via_email(email):
    try:
        user_obj = CustomUser.objects.get(email=email)
        # Now you can send the OTP email to the user
        # Example code for sending email...

        subject = 'Verification code is here'
        message = f'Your verification code is: {user_obj.verification_code}'
        from_email = settings.EMAIL_HOST_USER  # Use the email defined in settings.py
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)  # You can change fail_silently to True if you don't want to raise exceptions for any email sending failure
    except ObjectDoesNotExist:
        # Handle the case where the user does not exist
        # For example, you can log the error or return a response indicating the error
        print(f"User with email {email} does not exist")
