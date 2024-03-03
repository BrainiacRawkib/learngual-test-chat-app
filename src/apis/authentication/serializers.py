from rest_framework import serializers

from core import settings as core_settings
from apis.base import serializers_helpers as base_repo_serializer_helpers
from apis.clients import enums as client_enums, models as client_models
from apis.users import models as user_models


class TokenSerializer(serializers.Serializer):  # noqa
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    username = serializers.CharField()
    password = serializers.CharField()
    grant_type = serializers.CharField()
    scope = serializers.CharField()
    # redirect_uri = serializers.CharField()

    def validate(self, attrs):
        client_id = attrs['client_id']
        grant_type = attrs['grant_type']
        client = client_models.Client.get_by_id(client_id)

        if not client:
            raise serializers.ValidationError(
                'invalid_client'
            )

        if not client.validate_grant_type(grant_type):
            raise serializers.ValidationError(
                'invalid_grant_type'
            )
        return attrs


class RefreshTokenRequestSerializer(serializers.Serializer):  # noqa
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    code = serializers.CharField()
    grant_type = serializers.CharField()

    def save(self):
        tenant_id: str = self.context.get('tenant_id', '')
        user_id: str = self.context.get('user_id', '')
        two_fa_verified: bool = self.context.get('two_fa_verified', '')

        code = self.validated_data.get('code', '')

        user = user_models.User.get_by_id(id=user_id)
        refresh_token = client_models.RefreshToken.get_by_code(code)
        refresh_token.delete()
        new_refresh_token = client_models.RefreshToken.create(user_id)
        scope: str = 'offline_access email'

        if two_fa_verified:
            access_token = user.get_token_for_successful_2fa_verification(scope)
        else:
            access_token = user.get_token(scope)

        response_data: dict = {
            'access_token': access_token,
            'refresh_token': new_refresh_token.code,
            'token_type': 'Bearer',
            'expires_in': core_settings.TOKEN_EXPIRY_TIME,
            'scope': scope,
            'two_fa_enabled': user.two_fa_enabled,
            'two_fa_medium': user.two_fa_medium
        }
        return response_data

    def validate(self, attrs):
        user_id: str = self.context.get('user_id', '')

        client_id: str = attrs['client_id']
        grant_type: str = attrs['grant_type']
        code: str = attrs['code']

        client = client_models.Client.get_by_id(client_id)
        if not client:
            raise serializers.ValidationError(
                'invalid_client'
            )

        if not client.validate_grant_type(grant_type):
            raise serializers.ValidationError(
                'invalid_grant_type'
            )

        refresh_token = client_models.RefreshToken.get_by_code(code)
        if not refresh_token.is_valid(user_id):
            raise serializers.ValidationError(
                'Invalid refresh token!'
            )

        if grant_type != client_enums.GrantTypesEnum.REFRESH_TOKEN:
            raise serializers.ValidationError(
                'Invalid grant type!'
            )

        user = user_models.User.get_by_id(id=user_id)
        if not user.validate_user_against_client_id(client_id):
            raise serializers.ValidationError(
                'Invalid client and user!'
            )
        return attrs


class SendEmailConfirmationLinkRequestSerializer(serializers.Serializer):  # noqa
    email = serializers.EmailField(validators=[
        base_repo_serializer_helpers.validate_email
    ])


class ChangePasswordSerializer(serializers.Serializer):  # noqa
    current_password = serializers.CharField(validators=[
        base_repo_serializer_helpers.validate_password
    ])
    new_password = serializers.CharField(validators=[
        base_repo_serializer_helpers.validate_password
    ])


class ForgotPasswordRequestSerializer(serializers.Serializer):  # noqa
    email = serializers.CharField(validators=[
        base_repo_serializer_helpers.validate_email
    ])


class ResetPasswordSerializer(serializers.Serializer):  # noqa
    password = serializers.CharField(validators=[
        base_repo_serializer_helpers.validate_password
    ])
