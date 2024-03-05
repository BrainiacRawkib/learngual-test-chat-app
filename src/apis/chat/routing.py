from django.urls import re_path

from apis.chat import consumers


websocket_urlpatterns: list = [
    re_path(
        r'ws/chat/(?P<room_name>\w+)/$',
        consumers.ChatConsumer.as_asgi()
    )
]
