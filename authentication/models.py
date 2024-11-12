from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import MinLengthValidator, MinValueValidator, MaxValueValidator
from datetime import timedelta
from datetime import date, datetime
from django.utils import timezone
from dateutil.relativedelta import relativedelta
import time
import os
from django.utils.timezone import now
import uuid
# Create your models here.




def upload_to_s3_folder(instance, filename, folder_name='uploads'):
    """
    Generates a unique file path for S3 uploads by appending a timestamp to the file name.
    
    :param instance: The model instance that the file is being uploaded to.
    :param filename: The original name of the uploaded file.
    :param folder_name: Optional folder name where the file will be uploaded in S3.
    :return: A new file path with a timestamp to ensure uniqueness.
    """
    ext = filename.split('.')[-1]
    if folder_name == 'profile_pic':
        new_filename = f"user-X{instance.id}Y{instance.id}Z{instance.id}AB{instance.id}C-dp"
    # if folder_name == 'investment':
    #     new_filename = f"investmentr-A{instance.id}D{instance.id}C{instance.id}QY{instance.id}C-image"
    else:
        # Add a timestamp to the filename to ensure uniqueness
        timestamp = int(time.time())
        new_filename = f"{os.path.splitext(filename)[0]}_{timestamp}.{ext}"

    return f"{folder_name}/{new_filename}"
def upload_to_profile_pic(instance, filename):
    return upload_to_s3_folder(instance, filename, 'profile_pic')

class UserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email must be provided")
        if not password:
            raise ValueError("Password must be provided")
        user = self.model(email=self.normalize_email(email), role="ADMIN")
        user.set_password(password)
        user.save()
        return user

    def create_user(self, firstname, lastname,  email, phone, password=None, **extra_fields):
        if email is None:
            raise TypeError('Users should have an Email')
        if firstname is None:
            raise TypeError('Users should have a Firstname')
        if lastname is None:
            raise TypeError('Users should have a Lastname')
        if phone is None:
            raise TypeError('Users should have a phone number')

        user = self.model(firstname=firstname, lastname=lastname, email=self.normalize_email(
            email), phone=phone, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        if password is None:
            raise TypeError('Password should not be none')
        user = self._create_user(email, password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_verified = True
        user.role = "ADMIN"
        user.save()
        return user


USER_ROLES = [
    ("USERS", "General Users"),
    ("ADMIN", "Admin users"),
]


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    profile_picture = models.ImageField(upload_to=upload_to_profile_pic, null=True, blank=True)
    phone = models.CharField(
        max_length=255, unique=True, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_subscribed = models.BooleanField(default=False)
    
    role = models.CharField(
        max_length=255,
        choices=USER_ROLES,
        default=USER_ROLES[0][0]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstname', 'lastname', 'phone']

    objects = UserManager()

    def __str__(self):
        return f"{self.firstname} - {self.phone}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        db_table = "User"


class EmailVerification(models.Model):
    is_used = models.BooleanField(default=False)
    user = models.OneToOneField(to=User, on_delete=models.CASCADE)
    token = models.CharField(null=False, blank=False,
                             max_length=6, validators=[MinLengthValidator(6)])
    token_expiry = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.firstname} - {self.is_used}"

    class Meta:
        db_table = 'EmailVerification'

class ForgetPasswordToken(models.Model):
    is_used = models.BooleanField(default=False)
    user = models.OneToOneField(to=User, on_delete=models.CASCADE)
    token = models.CharField(null=False, blank=False,
                             max_length=6, validators=[MinLengthValidator(6)])
    token_expiry = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.firstname} - {self.is_used}"

    class Meta:
        db_table = 'PasswordReset'