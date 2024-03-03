import base64
import binascii

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BasicAuthentication, get_authorization_header

from apis.base import exceptions as custom_exceptions
from apis.clients import models as client_models


class BasicAuth(BasicAuthentication):
    """
     HTTP Basic authentication against username/password.
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Returns a `User` if a correct username and password have been supplied
        using HTTP Basic authentication.  Otherwise, returns `None`.
        """
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'basic':
            msg = _("The Authorization header isn't BASIC authorization header.")
            raise custom_exceptions.InvalidBasicHeader(msg)

        if len(auth) == 1:
            msg = _('Invalid basic header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid basic header. Credentials string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            try:
                auth_decoded = base64.b64decode(auth[1]).decode('utf-8')
            except UnicodeDecodeError:
                auth_decoded = base64.b64decode(auth[1]).decode('latin-1')
            auth_parts = auth_decoded.partition(':')
        except (TypeError, UnicodeDecodeError, binascii.Error):
            msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
            raise exceptions.AuthenticationFailed(msg)

        userid, password = auth_parts[0], auth_parts[2]
        return self.authenticate_credentials(userid, password, request)

    def authenticate_credentials(self, userid, password, request=None):
        """
        Authenticate the userid and password against username and password
        with optional request for context.
        """

        client = client_models.Client.get_by_id(userid)

        if client is None:
            raise exceptions.AuthenticationFailed(_('invalid_client'))

        if not client.validate_secret(password):
            raise exceptions.AuthenticationFailed(_('invalid_client_credentials'))

        return client, None

    def authenticate_header(self, request):
        return 'Basic realm="%s"' % self.www_authenticate_realm
