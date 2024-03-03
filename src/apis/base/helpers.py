import mimetypes

from datetime import datetime, timedelta
from threading import Thread

from bson import ObjectId
from django.contrib.auth.base_user import BaseUserManager
from django.core.management.utils import get_random_string

from core import settings as core_settings_base


DIGITS: str = "0123456789"


def generate_object_id() -> str:
    return f'{ObjectId()}'


def generate_otp() -> str:
    return get_random_string(6, DIGITS)


def generate_model_id(model_prefix: str) -> str:
    return f'{model_prefix}{generate_object_id()}'


def generate_transaction_ref() -> str:
    return f'trxn_ref_{get_random_string(12)}'


def generate_refresh_token_code() -> str:
    return f'{generate_object_id()}-{generate_otp()}-{get_random_string(12)}'


def get_file_size(file) -> int | float:
    """
    :param file: file to be uploaded
    returns file size
    """
    return round((file.size / 1024 / 1000), 2)


def file_size_gt_max_limit(file) -> bool:
    """
    check if file is larger than the MAX_FILE_SIZE
    """
    return get_file_size(file) > core_settings_base.MAX_FILE_SIZE


def get_valid_file_extensions(file, valid_extensions: list) -> bool:
    """
    valid_extensions should be retrieved from TenantDocument model in the `files` app.
    return True if file is part of the supported files.
    supported file extensions are .jpg, .png, .pdf.
    NB: Admin can add more if more features are required
    """

    valid_ext_mimetypes = []
    for ext in valid_extensions:
        # get the list of valid extensions and guess the mimetypes
        if ext.startswith('.'):
            # check if the extensions saved for each file on the db startswith `.`
            m = mimetypes.guess_type(f'file{ext.lower()}')[0]
        else:
            m = mimetypes.guess_type(f'file.{ext.lower()}')[0]
        valid_ext_mimetypes.append(m)
    if mimetypes.guess_type(file)[0] in valid_ext_mimetypes:
        return True
    return False


def generate_password() -> str:
    special_chars = get_random_string(3, '!@#$%^&*(-_=+)')
    digits = get_random_string(3, '0123456789')
    random_password = BaseUserManager().make_random_password()
    generated_password = f'{random_password}{digits}{special_chars}'
    return generated_password


def generate_zeros(no_of_zeros: int) -> str:
    return '0' * no_of_zeros


def generate_number(value: int) -> str:
    total_len_of_number = 5
    len_of_value = len(f'{value}')
    difference = total_len_of_number - len_of_value
    zeros = generate_zeros(difference - 1)
    return f'{zeros}{value}'


def queue_task(func, *args, **kwargs):
    consumer = Thread(target=func, args=args, kwargs=kwargs)
    consumer.start()
