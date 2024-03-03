from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework import status, exceptions
from rest_framework.response import Response
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList


def _get_error_details(data, default_code=None):  # noqa
    """
    Descend into a nested data structure, forcing any
    lazy translation strings or strings into `ErrorDetail`.
    """
    if isinstance(data, (list, tuple)):
        ret = [
            _get_error_details(item, default_code) for item in data
        ]
        if isinstance(data, ReturnList):
            return ReturnList(ret, serializer=data.serializer)
        return ret
    elif isinstance(data, dict):
        ret = {
            key: _get_error_details(value, default_code)
            for key, value in data.items()
        }
        if isinstance(data, ReturnDict):
            return ReturnDict(ret, serializer=data.serializer)
        return ret

    text = force_str(data)
    code = getattr(data, 'code', default_code)
    return ErrorDetail(text, code)


def _get_codes(message):
    if isinstance(message, list):
        return [_get_codes(item) for item in message]
    elif isinstance(message, dict):
        return {key: _get_codes(value) for key, value in message.items()}
    return message.code


def _get_full_details(message):
    if isinstance(message, list):
        return [_get_full_details(item) for item in message]
    elif isinstance(message, dict):
        return {key: _get_full_details(value) for key, value in message.items()}
    return {
        'message': message,
        'code': message.code
    }


class ErrorDetail(str):
    """
    A string-like object that can additionally have a code.
    """
    code = None

    def __new__(cls, string, code=None):
        self = super().__new__(cls, string)
        self.code = code
        return self

    def __eq__(self, other):
        result = super().__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        try:
            return result and self.code == other.code
        except AttributeError:
            return result

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    def __repr__(self):
        return 'ErrorDetail(string=%r, code=%r)' % (
            str(self),
            self.code,
        )

    def __hash__(self):
        return hash(str(self))


class CustomAPIException(Exception):
    """
    Base class for REST framework exceptions.
    Subclasses should provide `.status_code` and `.default_message` properties.
    """
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_message = _('A server error occurred.')
    default_code = 'error'

    def __init__(self, message=None, code=None):
        if message is None:
            message = self.default_message
        if code is None:
            code = self.default_code

        self.message = _get_error_details(message, code)

    def __str__(self):
        return str(self.message)

    def get_codes(self):
        """
        Return only the code part of the error messages.

        Eg. {"name": ["required"]}
        """
        return _get_codes(self.message)

    def get_full_details(self):
        """
        Return both the message & code parts of the error messages.

        Eg. {"name": [{"message": "This field is required.", "code": "required"}]}
        """
        return _get_full_details(self.message)


class AuthenticationError(CustomAPIException):
    status_code = 401
    default_message = _('Unauthenticated route access.')
    default_code = 'authentication_error'


class UnauthorizedUser(CustomAPIException):
    status_code = 403
    default_message = _('Unauthorized user.')
    default_code = 'unauthorized_user'


class InvalidJWT(CustomAPIException):
    status_code = 401
    default_message = _('Invalid Token.')
    default_code = 'invalid_token'


class JWTExpired(CustomAPIException):
    status_code = 401
    default_message = _('Token has expired.')
    default_code = 'token_expired'


class InvalidBearerHeader(CustomAPIException):
    status_code = 401
    default_message = _("The Authorization header isn't BEARER authorization header.")
    default_code = 'invalid_bearer_header'


class InvalidBasicHeader(CustomAPIException):
    status_code = 401
    default_message = _("The Authorization header isn't BASIC authorization header.")
    default_code = 'invalid_basic_header'


class InvalidUser(CustomAPIException):
    status_code = 404
    default_message = _("User associated with access token does not exist.")
    default_code = 'user_does_not_exist'


class AccountNotActivated(CustomAPIException):
    status_code = 403
    default_message = _("Account not activated.")
    default_code = 'account_not_activated'


class AccountDeactivated(CustomAPIException):
    status_code = 403
    default_message = _("Account is deactivated.")
    default_code = 'account_is_deactivated'


def exception_handler(exc, context):
    """
    Returns the response that should be used for any given exception.

    By default, we handle the REST framework `APIException`, and also
    Django's built-in `Http404` and `PermissionDenied` exceptions.

    Any unhandled exceptions may return `None`, which will cause a 500 error
    to be raised.
    """
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    headers = {}
    if isinstance(exc, exceptions.Throttled):
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        data = {
            'message': exc.default_detail
        }
        return Response(data, status=exc.status_code, headers=headers)
    elif isinstance(exc, exceptions.MethodNotAllowed):
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa

        message = exc.default_detail.format(method=exc.args[0])
        data = {
            'message': message
        }
        return Response(data, status=exc.status_code, headers=headers)
    elif isinstance(exc, exceptions.NotAcceptable):
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa

        data = {
            'message': exc.default_detail,
            'renderers': exc.available_renderers
        }
        return Response(data, status=exc.status_code, headers=headers)
    elif isinstance(exc, exceptions.UnsupportedMediaType):
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa

        data = {
            'message': exc.default_detail.format(media_type=exc.args[0])
        }
        return Response(data, status=exc.status_code, headers=headers)
    elif isinstance(exc, exceptions.APIException):  # rest framework base APIException. NB: do not edit
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait  # noqa

        if isinstance(exc.detail, (list, dict)):  # noqa
            data = exc.detail  # noqa
        else:
            data = {
                'message': exc.detail  # noqa
            }
        return Response(data, status=exc.status_code, headers=headers)
    elif isinstance(exc, CustomAPIException):  # custom base CustomAPIException. NB: do not edit
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header  # noqa
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait  # noqa

        if isinstance(exc.message, (list, dict)):
            data = exc.message
        else:
            data = {
                'message': exc.message
            }
        return Response(data, status=exc.status_code, headers=headers)
    else:
        return None


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        response.data['statusCode'] = response.status_code
    else:
        response = Response(data={
            'statusCode': 500,
            'message': 'Internal Server Error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return response
