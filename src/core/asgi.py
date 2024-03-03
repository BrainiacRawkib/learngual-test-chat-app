"""
ASGI config for core project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

from apis.authentication.middleware import WebSocketJWTAuthMiddleware


os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"core.settings")

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': AllowedHostsOriginValidator(
        WebSocketJWTAuthMiddleware(
            URLRouter(
                websocket_urlpatterns
            )
        ),
    ),
    # 'websocket': OriginValidator(
    #     WebSocketJWTAuthMiddleware(
    #         URLRouter(
    #             websocket_urlpatterns
    #         )
    #     ),
    #     base.ALLOWED_HOSTS
    # )
})