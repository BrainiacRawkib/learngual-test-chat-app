from apis.base import helpers as base_repo_helpers, enums as base_repo_enums


def generate_user_id() -> str:
    return base_repo_helpers.generate_model_id(base_repo_enums.ModelPrefixEnum.USER)
