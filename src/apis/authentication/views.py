from django.contrib.auth.tokens import default_token_generator
from django.http import JsonResponse
from django.shortcuts import render
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser

from core import settings as core_settings
from apis.authentication import serializers as auth_serializers
from apis.base import responses as base_repo_responses, views as base_repo_views
from apis.clients import models as client_models
from apis.users import models as user_models


class TokenAPIView(base_repo_views.BasicAuthenticationAPIView):
    parser_classes = [FormParser, JSONParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        try:
            serializer = auth_serializers.TokenSerializer(
                data=request.data
            )
            if serializer.is_valid():
                data: dict = serializer.validated_data
                email: str = data['email']
                password: str = data['password']

                user = user_models.User.get_by_email(email=email)
                if not user:
                    errors: dict = {
                        'error_message': 'invalid_user'
                    }
                    return base_repo_responses.http_response_401(
                        'Authentication Error!', errors=errors
                    )

                if not user.is_active:
                    errors: dict = {
                        'error_message': 'invalid_user'
                    }
                    return base_repo_responses.http_response_401(
                        'Authentication Error!', errors=errors
                    )

                if not user.validate_password(password):
                    errors: dict = {
                        'error_message': 'invalid_user_credentials'
                    }
                    return base_repo_responses.http_response_401(
                        'Authentication Error!', errors=errors
                    )

                refresh_token = client_models.RefreshToken.create(user.id)
                response_data: dict = {
                    'access_token': user.get_token,
                    'refresh_token': refresh_token.code,
                    'token_type': 'Bearer',
                    'expires_in': core_settings.TOKEN_EXPIRY_TIME
                }
                return JsonResponse(response_data, safe=False)
            return base_repo_responses.http_response_400(
                'Bad request!', errors=serializer.errors
            )
        except Exception as e:  # noqa
            self._log.error('TokenAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class RefreshTokenAPIView(base_repo_views.TokenAuthenticationAPIView):
    parser_classes = [FormParser]

    def post(self, request, *args, **kwargs):
        try:
            two_fa_verified: bool = request.two_fa_verified
            tenant_id: str = request.tenant_id
            user_id: str = request.user_id

            context: dict = {
                'tenant_id': tenant_id,
                'user_id': user_id,
                'two_fa_verified': two_fa_verified
            }
            serializer = auth_serializers.RefreshTokenRequestSerializer(
                data=request.data, context=context
            )
            if serializer.is_valid():
                response_data = serializer.save()
                return base_repo_responses.http_response_200(
                    'Authentication successful!', data=response_data
                )
            return base_repo_responses.http_response_400(
                'Bad request!', errors=serializer.errors
            )
        except Exception as e:  # noqa
            self._log.error('RefreshTokenAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class SetPasswordAPIView(base_repo_views.BasicAuthenticationAPIView):

    def post(self, request, *args, **kwargs):
        try:
            query_params = request.query_params
            uid = urlsafe_base64_decode(query_params.get('uid', '')).decode()
            user = user_models.User.get_by_id(id=uid)
            if not user:
                return base_repo_responses.http_response_400(
                    'Invalid set password token!'
                )

            token = query_params.get('token', '')
            token = client_models.PasswordResetUrl.get_by_token(token=token)
            if user and token.is_valid(user.id):
                serializer = auth_serializers.ResetPasswordSerializer(
                    data=request.data
                )
                if serializer.is_valid():
                    data = serializer.validated_data
                    password = data['password']

                    user.set_new_password = password
                    user.save()

                    token.used = True
                    token.save()
                    return base_repo_responses.http_response_200(
                        'Password set successfully!'
                    )
                return base_repo_responses.http_response_400(
                    'Bad request!', errors=serializer.errors
                )
            return base_repo_responses.http_response_401(
                'Invalid set password link!'
            )
        except Exception as e:  # noqa
            self._log.error('SetPasswordAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class ChangePasswordAPIView(base_repo_views.TokenAuthenticationAPIView):

    def post(self, request, *args, **kwargs):
        try:
            user = user_models.User.get_by_id(id=request.user_id)
            serializer = auth_serializers.ChangePasswordSerializer(
                data=request.data
            )
            if serializer.is_valid():
                data = serializer.validated_data
                current_password = data['current_password']
                new_password = data['new_password']

                if not user.validate_password(current_password):
                    return base_repo_responses.http_response_400(
                        'Incorrect password!'
                    )

                user.set_new_password = new_password
                user.save()
                return base_repo_responses.http_response_200(
                    'Password changed successfully!'
                )
            return base_repo_responses.http_response_400(
                'Bad request!', errors=serializer.errors
            )
        except Exception as e:  # noqa
            self._log.error('ChangePasswordAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class ForgotPasswordAPIView(base_repo_views.BasicAuthenticationAPIView):

    def post(self, request, *args, **kwargs):
        try:
            serializer = auth_serializers.ForgotPasswordRequestSerializer(
                data=request.data
            )
            if serializer.is_valid():
                data: dict = serializer.validated_data
                email: str = data['email']
                user = user_models.User.get_by_email(email=email)
                if user:
                    user_id = user.id
                    uid = urlsafe_base64_encode(force_bytes(user_id))
                    token = default_token_generator.make_token(user)
                    base_url: str = core_settings.BASE_URL
                return base_repo_responses.http_response_200(
                    'A link has been sent to your email with instructions to reset your password!'
                )
            return base_repo_responses.http_response_400(
                'Bad request!', errors=serializer.errors
            )
        except Exception as e:  # noqa
            self._log.error('ForgotPasswordAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class VerifyPasswordResetTokenAPIView(base_repo_views.BasicAuthenticationAPIView):

    def get(self, request, *args, **kwargs):
        try:
            query_params = request.query_params
            try:
                uid = urlsafe_base64_decode(query_params.get('uid', '')).decode()
                user = user_models.User.get_by_id(id=uid)
                token = query_params.get('token', '')
                decoded_token = default_token_generator.check_token(user, token)
            except UnicodeDecodeError:
                return base_repo_responses.http_response_401(
                    'Invalid password reset token!'
                )

            if not user:
                return base_repo_responses.http_response_400(
                    'Invalid reset token!'
                )

            if user and decoded_token:
                user_id = user.id
                uid = urlsafe_base64_encode(force_bytes(user_id))
                new_token: str = default_token_generator.make_token(user)
                base_url: str = core_settings.BASE_URL
                reset_link: str = f'{base_url}/auth/reset-password?uid={uid}&token={new_token}'
                password_reset_url_payload: dict = {
                    'user_id': user.id,
                    'token': new_token
                }
                client_models.PasswordResetUrl.create(password_reset_url_payload)
                data: dict = {
                    'url': reset_link
                }
                return base_repo_responses.http_response_200(
                    'Password reset link verified successfully!', data=data
                )
            return base_repo_responses.http_response_401(
                'Password reset token has expired!'
            )
        except Exception as e:  # noqa
            self._log.error('VerifyPasswordResetTokenAPIView.get@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


class ResetPasswordAPIView(base_repo_views.BasicAuthenticationAPIView):

    def post(self, request, *args, **kwargs):
        try:
            query_params = request.query_params
            try:
                uid = urlsafe_base64_decode(query_params.get('uid', '')).decode()
                user = user_models.User.get_by_id(id=uid)
            except UnicodeDecodeError:
                return base_repo_responses.http_response_401(
                    'Invalid password reset link!'
                )

            if not user:
                return base_repo_responses.http_response_400(
                    'Invalid reset token!'
                )

            token = query_params.get('token', '')
            token = client_models.PasswordResetUrl.get_by_token(token=token)
            if user and token and token.is_valid(user.id):
                serializer = auth_serializers.ResetPasswordSerializer(
                    data=request.data
                )
                if serializer.is_valid():
                    data: dict = serializer.validated_data
                    password: str = data['password']

                    user.set_new_password = password
                    user.save()

                    token.used = True
                    token.save()
                    return base_repo_responses.http_response_200(
                        'Password reset successfully!'
                    )
                return base_repo_responses.http_response_400(
                    'Bad request!', errors=serializer.errors
                )
            return base_repo_responses.http_response_401(
                'Password reset link has expired!'
            )
        except Exception as e:  # noqa
            self._log.error('ResetPasswordAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)


def login(request):
    return render(request, template_name='login.html')
