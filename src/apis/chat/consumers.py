import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer

from apis.users import models as users_models


log = logging.getLogger(__name__)


class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        # NB: the self.room_name must match the first args in the `channel_layer.group_send()`
        # variable in tasks.py else the broadcast won't be triggered

        userId = self.scope["ws_user_id"]  # value set in the notifications middleware
        self.room_name = userId

        # Join room group
        await self.channel_layer.group_add(
            self.room_name, self.channel_name
        )
        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(
            self.room_name, self.channel_name
        )

    async def send_message(self, event):
        # this method is connected to the `sendNotification` and `sendUnicast` tasks in tasks.py in the
        # `channel_layer.group_send()` variable
        # NB: if this method isn't called exactly the same way it is
        # written here, the broadcast won't be triggered
        message = json.loads(event['data'])
