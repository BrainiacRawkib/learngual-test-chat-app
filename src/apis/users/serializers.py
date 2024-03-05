from rest_framework import serializers

from apis.base import serializers_helpers as base_repo_serializers_helpers
from apis.users import models as user_models


class SignupRequestSerializer(serializers.ModelSerializer):
    password = serializers.CharField(validators=[
        base_repo_serializers_helpers.validate_password
    ])

    class Meta:
        model = user_models.User
        fields = ['email', 'password']

    def create(self, validated_data):
        try:
            payload: dict = {
                'email': validated_data.get('email', ''),
                'password': validated_data.get('password', '')
            }
            user = user_models.User.create(payload)
            return user
        except Exception:
            return None

    def validate(self, attrs):
        email = attrs['email']
        user = user_models.User.get_by_email(email)
        if user:
            raise serializers.ValidationError(
                'User with email already exist!'
            )
        return attrs
