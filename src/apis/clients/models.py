from base64 import b64encode
from datetime import timedelta, datetime

from django.contrib.auth.tokens import default_token_generator
from django.db import models
from django.utils import timezone

from core import settings as core_settings
from apis.base import helpers as base_repo_helpers, models as base_repo_models
from apis.clients import models_helpers as client_models_helpers
from apis.users import models as user_models


class Client(base_repo_models.BaseModel):
    id = models.CharField(primary_key=True, db_index=True, max_length=100, editable=False)
    client_id = models.CharField(max_length=150)
    client_secret = models.TextField()
    name = models.CharField(max_length=100)
    response_type = models.CharField(max_length=200)
    scope = models.CharField(max_length=200)
    grant_types = models.CharField(max_length=200)
    redirect_uris = models.CharField(max_length=200)

    def validate_secret(self, secret: str) -> bool:
        encode_secret = Client.encode_client_secret(secret)
        return encode_secret == self.client_secret

    def validate_scope(self, scope: str) -> bool:
        scopes = scope.split(' ')
        for scp in scopes:
            if scp not in self.scope.split(' '):
                return False
        return True

    def validate_grant_type(self, grant_type: str) -> bool:
        grant_types = grant_type.split(' ')
        for g_type in grant_types:
            if g_type not in self.grant_types.split(' '):
                return False
        return True

    def validate_redirect_uri(self, redirect_uri: str) -> bool:
        redirect_uris = redirect_uri.split(' ')
        for uri in redirect_uris:
            if uri not in self.redirect_uris.split(' '):
                return False
        return True

    @staticmethod
    def encode_client_secret(secret: str) -> str:
        return b64encode(secret.encode('utf-8')).decode()

    @staticmethod
    def create(payload: dict) -> "Client":
        base64_encoded_secret = Client.encode_client_secret(payload['client_secret'])
        return Client.objects.create(
            id=payload['client_id'],
            client_id=payload['client_id'],
            client_secret=base64_encoded_secret,
            name=payload['client_id'],
            response_type=payload['response_type'],
            scope=payload['scope'],
            grant_types=payload['grant_types'],
            redirect_uris=payload['redirect_uris']
        )

    @staticmethod
    def get_by_id(client_id: str):
        try:
            return Client.objects.get(id=client_id)
        except (Exception, Client.DoesNotExist):
            return None


class RefreshToken(base_repo_models.BaseModel):
    id = models.CharField(primary_key=True, editable=False, db_index=True, max_length=60, default=client_models_helpers.generate_refresh_token_id, unique=True)
    code = models.CharField(max_length=70, default="", db_index=True)
    user_id = models.CharField(max_length=70, default="")
    used = models.BooleanField(default=True)
    expiry_time = models.DateTimeField(default=timezone.now)

    def is_valid(self, user_id: str) -> bool:
        if self.user_id == user_id and self.expiry_time > timezone.now():
            return True
        return False

    @staticmethod
    def refresh_token_generator() -> tuple[str, datetime]:
        code = base_repo_helpers.generate_refresh_token_code()
        expiry_time = timezone.now() + timedelta(minutes=core_settings.REFRESH_TOKEN_EXPIRY_TIME)
        return code, expiry_time

    @staticmethod
    def create(user_id: str):
        code, expiry_time = RefreshToken.refresh_token_generator()
        return RefreshToken.objects.create(
            user_id=user_id,
            code=code,
            used=False,
            expiry_time=expiry_time
        )

    @staticmethod
    def get_by_code(code: str):
        try:
            return RefreshToken.objects.get(code=code)
        except (Exception, RefreshToken.DoesNotExist):
            return None

    @staticmethod
    def scheduler_get_used_or_expired_refresh_tokens():
        now = timezone.now()
        return RefreshToken.objects.filter(
            models.Q(used=True) | models.Q(expiry_time__lt=now)
        )


class PasswordResetUrl(base_repo_models.BaseModel):
    id = models.CharField(primary_key=True, editable=False, db_index=True, max_length=60, default=client_models_helpers.generate_password_reset_token_id, unique=True)
    user_id = models.CharField(max_length=70, default="")
    used = models.BooleanField(default=True)
    token = models.CharField(max_length=100, default="", db_index=True)

    def is_valid(self, user_id: str) -> bool:
        user = user_models.User.get_by_id(id=self.user_id)
        token = default_token_generator.check_token(user, self.token)
        if self.user_id == user_id and not self.used and token:
            return True
        return False

    @staticmethod
    def create(payload: dict):
        return PasswordResetUrl.objects.create(
            user_id=payload.get('user_id', ''),
            token=payload.get('token', ''),
            used=False
        )

    @staticmethod
    def get_by_token(token: str):
        try:
            return PasswordResetUrl.objects.get(token=token)
        except (Exception, PasswordResetUrl.DoesNotExist):
            return None

    @staticmethod
    def scheduler_get_used_or_expired_password_reset_tokens():
        time_delta = timezone.now() - timedelta(minutes=13)
        return PasswordResetUrl.objects.filter(
            models.Q(used=True) | models.Q(date_created__lte=time_delta)
        )
