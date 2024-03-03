from enum import StrEnum


class ModelPrefixEnum(StrEnum):
    PASSWORD_RESET_TOKEN = 'pswd_rst_tkn_'
    REFRESH_TOKEN = 'rfsh_tkn_'
    ROOM = 'room_'
    USER = 'user_'
