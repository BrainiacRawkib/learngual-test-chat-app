from apis.base import helpers as base_repo_helpers, enums as base_repo_enums


def generate_refresh_token_id():
    return base_repo_helpers.generate_model_id(base_repo_enums.ModelPrefixEnum.REFRESH_TOKEN)


def generate_password_reset_token_id():
    return base_repo_helpers.generate_model_id(base_repo_enums.ModelPrefixEnum.PASSWORD_RESET_TOKEN)
