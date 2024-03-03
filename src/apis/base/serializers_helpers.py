"""
the general fields to be excluded from the request payload. This function must be used when a serializer class
is a ModelSerializer class and also using the `exclude` option and not the `field` option in the `class Meta`
"""
import re

from django.utils import timezone
from rest_framework import serializers


def base_excluded_fields(arr: list[str] = None) -> list:
    base_fields = ['date_created', 'date_updated', 'tenant_id', 'id']
    if arr:
        base_fields.extend(arr)
    return base_fields


def validate_future_date(value):
    if value > timezone.now():
        raise serializers.ValidationError(
            'Date cannot be a future date!'
        )
    return value


def validate_past_date(value):
    if value < timezone.now():
        raise serializers.ValidationError(
            'Date cannot be a past date!'
        )
    return value


def validate_name(name: str):
    """
    validate first_name and last_name
    """
    name_pattern = re.compile(r'^[a-zA-Z]{3,}$')
    if not name_pattern.match(name):
        raise serializers.ValidationError(
            'Names must be at least 3 characters and must not contain white space, underscores or any special characters!'
        )
    return name


def validate_password(password: str):
    password_pattern = re.compile(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?\d)(?=.*?\W).{8,}$')
    if not password_pattern.match(password):
        raise serializers.ValidationError('Password must be at least 8 characters long, at least one number '
                                          'and both lower and uppercase letters and special characters!')
    return password


def validate_login_pin(login_pin: str):
    login_pin_pattern = re.compile(r'^\d{6}$')
    if not login_pin_pattern.match(login_pin):
        raise serializers.ValidationError('Login pin must be 6 digits!')
    return login_pin


def validate_email(email: str):
    email_pattern = re.compile(r'^[a-zA-Z\d._]+@\w+[.]\w{2,}$')
    if not email_pattern.match(email):
        raise serializers.ValidationError(
            'Invalid email format!'
        )
    return email


def validate_phone_number(phone_number: str):
    phone_number_pattern = re.compile(r'^\d{11}$')
    if not phone_number_pattern.match(phone_number):
        raise serializers.ValidationError('Phone number must be 11 digits!')
    return phone_number


def validate_country_code(country_code: str):
    country_code_pattern = re.compile(r'^\+\d+$')
    if not country_code_pattern.match(country_code):
        raise serializers.ValidationError('Country Code must start with +xx e.g +234!')
    return country_code
