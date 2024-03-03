from rest_framework.response import Response
from rest_framework import status


""" custom response """

def custom_response(msg: str, data: dict = None, errors: dict = None, **kwargs):  # noqa
    response_data = {
        'message': msg
    }

    if data is not None:
        response_data.update({
            'data': data
        })

    return Response(
        response_data,
        status=status.HTTP_200_OK,
        **kwargs
    )


""" 2xx responses """

def http_response_200(msg: str, data: dict = None, headers: dict = None):
    response_data = {
        'message': msg
    }

    if data is not None:
        response_data.update({
            'data': data
        })

    return Response(
        response_data,
        status=status.HTTP_200_OK,
        headers=headers
    )


def http_response_201(msg: str, data: dict = None):
    response_data = {
        'message': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_201_CREATED
    )


""" 4xx responses """

def http_response_400(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        if isinstance(errors, list):
            for d in errors:
                response_data.update({
                    'message': d[''][0],
                })
                return Response(
                    response_data,
                    status=status.HTTP_400_BAD_REQUEST
                )
        elif isinstance(errors, dict):
            # this fix is used for returning just one error's response
            # at a time during validation, since DRF returns all validation
            # errors (through serializers.errors) response at once.
            for keys, values in errors.items():
                if isinstance(values, dict):
                    for k, v in values.items():
                        if isinstance(v, dict):
                            for a, b in v.items():
                                retA = f'{a}:' if a else ''
                                response_data.update({
                                    'message': f"{retA} {b[0]}",
                                })
                            return Response(
                                response_data,
                                status=status.HTTP_400_BAD_REQUEST
                            )
                        retK = f'{k}:' if k else ''
                        response_data.update({
                            'message': f"{retK} {v[0]}"
                        })
                        return Response(
                            response_data,
                            status=status.HTTP_400_BAD_REQUEST
                        )
                retKeys = f'{keys}:' if keys else ''
                response_data.update({
                    'message': f"{retKeys} {values[0]}"
                })
                return Response(
                    response_data,
                    status=status.HTTP_400_BAD_REQUEST
                )

    return Response(
        response_data,
        status=status.HTTP_400_BAD_REQUEST
    )


def http_response_401(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_401_UNAUTHORIZED
    )


def http_response_403(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_403_FORBIDDEN
    )


def http_response_404(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_404_NOT_FOUND
    )


def http_response_409(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_409_CONFLICT
    )


def http_response_429(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_429_TOO_MANY_REQUESTS
    )


""" 5xx responses """

def http_response_500(msg: str, data: dict = None, errors: dict = None):  # noqa
    response_data = {
        'message': msg
    }

    if errors is not None:
        response_data.update({
            'errors': errors,
        })

    return Response(
        response_data,
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
