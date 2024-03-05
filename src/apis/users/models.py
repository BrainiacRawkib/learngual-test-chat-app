from datetime import timedelta

import jwt

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from core import settings as core_settings
from apis.base import models as base_repo_models
from apis.users import model_helpers as user_model_helpers


class User(base_repo_models.BaseModel, AbstractUser):
    id = models.CharField(primary_key=True, default=user_model_helpers.generate_user_id, db_index=True, max_length=60, editable=False, unique=True)
    first_name = models.CharField(max_length=100, default="", blank=True)
    middle_name = models.CharField(max_length=100, default="", blank=True)
    last_name = models.CharField(max_length=100, default="", blank=True)
    email = models.EmailField(max_length=100, default="", blank=True)
    username = models.EmailField(max_length=100, default="", blank=True, unique=True)  # username is an email in this context
    password = models.CharField(max_length=240, default="", blank=True, null=True)

    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "email"]
    USERNAME_FIELD = "username"

    class Meta:
        ordering = ['first_name', 'last_name']

    def validate_password(self, password: str) -> bool:
        return self.check_password(password)

    @property
    def get_token(self) -> str:
        key = core_settings.PRIVATE_KEY
        alg = core_settings.SIGNING_ALGORITHM
        aud = core_settings.AUDIENCE
        now = timezone.now()

        headers: dict = {
            'alg': alg
        }

        payload: dict = {
            'iss': core_settings.ISSUER,
            'sub': self.id,
            'email': self.email,
            'iat': now,
            'aud': aud,
            'exp': now + timedelta(seconds=core_settings.TOKEN_EXPIRY_TIME)
        }
        token = jwt.encode(payload, key, algorithm=alg, headers=headers)
        self.last_login = now
        self.save()
        return token

    @staticmethod
    def create(payload: dict):
        return User.objects.create(
            first_name=payload.get('first_name', ''),
            last_name=payload.get('last_name', ''),
            email=payload.get('email', ''),
            username=payload.get('email', ''),
            password=make_password(payload.get('password', None))
        )

    @staticmethod
    def get_by_id(id: str):  # noqa
        try:
            return User.objects.get(id=id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def aget_by_id(id: str):  # noqa
        try:
            return User.objects.aget(id=id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def get_by_email(email: str):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None
