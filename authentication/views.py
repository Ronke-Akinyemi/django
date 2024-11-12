import base64
from decouple import config
from datetime import timedelta
from django.utils import timezone
from rest_framework import generics, status, views, permissions, parsers
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import hashlib
from django.http import HttpResponsePermanentRedirect, HttpResponse
from django.db import transaction

from authentication.models import User, EmailVerification, ForgetPasswordToken
from .serializers import (
    SignupSerializer,
    ResendVerificationMailSerializer,
    LoginSerializer,
    PhoneVerificationSerializer,
    RequestPasswordResetPhoneSerializer,
    SetNewPasswordSerializer,
    ChangePasswordSerializer,
    PhoneCodeVerificationSerializer,
)
from utils.email import SendMail
from utils.sms import SendSMS



class SignupView(generics.GenericAPIView):
    serializer_class = SignupSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # check that user doesn't exist
        user = User.objects.filter(email=serializer.validated_data['email']).first()
        if user:
            return Response({
                "status_code": 400,
                "error": "User with email already exists",
                "payload": []
            }, status.HTTP_400_BAD_REQUEST)
        phone = User.objects.filter(phone=serializer.validated_data['phone']).first()
        if phone:
            return Response({
                "status_code": 400,
                "error": "User with phone number already exists",
                "payload": []
            }, status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            # persist user in db
            user = serializer.save()
            # generate email verification token
            token = User.objects.make_random_password(length=6, allowed_chars=f'0123456789')
            token_expiry = timezone.now() + timedelta(minutes=10)
            EmailVerification.objects.create(user=user, token=token, token_expiry=token_expiry)
            data = {"token": token, 'number': user.phone}
            SendSMS.sendVerificationCode(data)
        return Response({
            "message": "Registration successful"
        }, status=status.HTTP_201_CREATED)


class ResendVerificationMail(generics.GenericAPIView):
    serializer_class = ResendVerificationMailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        verification_obj = serializer.validated_data

        with transaction.atomic():
            if verification_obj:
                # generate email verification token
                token = User.objects.make_random_password(length=6, allowed_chars=f'0123456789')
                token_expiry = timezone.now() + timedelta(minutes=10)
                verification_obj.token = token
                verification_obj.token_expiry = token_expiry
                verification_obj.save()
                data = {"token": token, 'number': verification_obj.user.phone}
                SendSMS.sendVerificationCode(data)

        return Response({
            "message": "check phone for verification code",
        }, status=200)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response( serializer.data, status=status.HTTP_200_OK)


class VerifyPhone(generics.GenericAPIView):
    serializer_class = PhoneVerificationSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({"message": "success"}, status=status.HTTP_200_OK)





class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = ['http', 'https']


class RequestPasswordResetPhoneView(generics.GenericAPIView):
    serializer_class = RequestPasswordResetPhoneSerializer

    def post(self, request):
        # validate request body
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # serializer validated_data retuns custom "False" value if encounters error
        if serializer.validated_data:
            # send sms
            data = {"token": serializer.validated_data["token"], 'number': serializer.validated_data["phone"]}
            SendSMS.sendVerificationCode(data)
        return Response({
            'message': 'we have sent you a code to reset your password'
        }, status=status.HTTP_200_OK)

class VerifyPasswordResetCode(generics.GenericAPIView):
    serializer_class = PhoneCodeVerificationSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        return Response(data=data, status=status.HTTP_200_OK)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):

        serializer = self.serializer_class(instance=request.user, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'message': 'password change successful'}, status=status.HTTP_200_OK)
