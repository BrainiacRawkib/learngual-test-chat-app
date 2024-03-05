import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone


log = logging.getLogger(__name__)


class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        # NB: the self.room_name must match the first args in the `channel_layer.group_send()`
        # variable in tasks.py else the broadcast won't be triggered

        self.room_name = self.scope["url_route"]["kwargs"]["room_name"]
        self.room_group_name = f"chat_{self.room_name}"

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name, self.channel_name
        )

        # accept connection
        await self.accept()

    async def disconnect(self, code):
        # disconnect
        await self.channel_layer.group_discard(
            self.room_group_name, self.channel_name
        )

    async def receive(self, text_data=None, bytes_data=None):
        # receive message from WebSocket
        text_data_json = json.loads(text_data)

        message = text_data_json["message"]

        # send message to room group
        await self.channel_layer.group_send(
            self.room_group_name, {
                "type": "chat_message",
                "message": message,
                'datetime': timezone.now().isoformat()
            }
        )

    # Receive message from room group
    async def chat_message(self, event):
        message = event["message"]

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            "user_id": self.scope['ws_user_id'],
            "message": message
        }))
