import logging

from datetime import datetime

from rest_framework.authentication import get_authorization_header
from django.utils.translation import gettext_lazy as _

from apis.authentication import bearer as bear_token_auth
from apis.users import models as user_models
from apis.base import exceptions as custom_exceptions


log = logging.getLogger(__name__)


class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # set the following values before getting the response i.e self.get_response(request)
        # because the response would have processed the initial request and will invalidate
        # any other request

        auth = get_authorization_header(request).split()

        if len(auth) == 2:
            auth_keyword, auth_secret = auth[0].decode(), auth[1].decode()
            if auth_keyword.lower() == 'bearer':
                token_auth = bear_token_auth.TokenAuthentication()
                token_auth_payload, _ = token_auth.authenticate_token(auth_secret)

                if token_auth_payload and isinstance(token_auth_payload, dict):
                    request.tenant_type = token_auth_payload.get('tenant_type', '')
                    request.tenant_id = token_auth_payload.get('tenant_id', '')
                    request.tenant_name = token_auth_payload.get('tenant_name', '')
                    request.role = token_auth_payload.get('role', '')
                    request.user_id = token_auth_payload.get('sub', '')
                    request.user_email = token_auth_payload.get('email', '')
                    request.full_name = token_auth_payload.get('full_name', '')
                    request.scope = token_auth_payload.get('scope', '')
                    request.two_fa_verified = token_auth_payload.get('two_fa_verified', False)
        response = self.get_response(request)
        return response


class WebSocketJWTAuthMiddleware:
    keyword = 'Bearer'

    def __init__(self, app):
        # Store the ASGI application we were passed
        self.app = app

    async def __call__(self, scope, receive, send):

        try:
            query_string = scope["query_string"].decode()
            token = query_string.split('=')[1]
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise custom_exceptions.AuthenticationError(msg)

        jwt_payload, _ignore = bear_token_auth.TokenAuthentication().authenticate_token(token)

        if jwt_payload and isinstance(jwt_payload, dict):
            if datetime.now() > jwt_payload['expiry_time']:
                # if the token has expired, set the ws_user_id and ws_tenant_id to empty string
                scope["ws_user_id"] = ''
                scope["ws_tenant_id"] = ''
                raise Exception('Token has expired!')
            else:
                scope["ws_user_id"] = jwt_payload['sub']
                scope["ws_tenant_id"] = jwt_payload['tenant_id']

                userId = scope["ws_user_id"]
                user = user_models.User.get_by_id(userId)
                if not user:
                    log.error('WebSocketJWTAuthMiddleware.Error')
                    raise Exception('User does not exist!')

        return await self.app(scope, receive, send)
