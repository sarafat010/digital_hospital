"""
ASGI config for hospital_management project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
from . import consumers


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hospital_management.settings")

#application = get_asgi_application()

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/video_chat/<int:room_id>/", consumers.VideoChatConsumer.as_asgi()),
        ])
    ),
})
