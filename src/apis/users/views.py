from apis.base import responses as base_repo_responses, views as base_repo_views
from apis.users import serializers as user_serializers


class SignUpAPIView(base_repo_views.BasicAuthenticationAPIView):

    def post(self, request, *args, **kwargs):
        try:
            serializer = user_serializers.SignupRequestSerializer(
                data=request.data
            )
            if serializer.is_valid():
                data: dict = serializer.validated_data
                created_user = serializer.create(data)
                data.update({
                    'user_id': created_user.id
                })
                return base_repo_responses.http_response_200(
                    'Account created successfully!', data=data
                )
            return base_repo_responses.http_response_400(
                'Bad request!', errors=serializer.errors
            )
        except Exception as e:
            self._log.error('SignUpAPIView.post@Error')
            self._log.error(e)
            return base_repo_responses.http_response_500(self.server_error_msg)
