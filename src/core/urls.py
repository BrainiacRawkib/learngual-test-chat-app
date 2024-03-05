from django.contrib import admin
from django.urls import include, path, re_path

from apis.base import views as base_views


urlpatterns: list = [
    path("admin/", admin.site.urls),
    path("auth/", include("apis.authentication.urls", namespace='authentication')),
    path("chat/", include("apis.chat.urls", namespace='chat')),
    path("users/", include("apis.users.urls", namespace='users')),
    re_path(r'^.*$', base_views.NotFoundAPIView.as_view())
]
