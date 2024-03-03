from enum import StrEnum


class ClientTypeEnum(StrEnum):
    SUPER_ADMIN_USER_CLIENT: str = "NAFESuperAdminClient"
    DEPT_ADMIN_USER_CLIENT: str = "NAFEDeptAdminClient"
    APP_CLIENT: str = "NAFEAppClient"
