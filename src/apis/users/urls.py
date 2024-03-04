from django.urls import path

from apis.users import views as user_views


app_name: str = "users"

urlpatterns: list = [
    path(
        'add',
        user_views.SignUpAPIView.as_view(),
        name='add'
    )
]
