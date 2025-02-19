import json
from channels.generic.websocket import AsyncWebsocketConsumer

class VideoChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        self.room_group_name = f'video_chat_{self.room_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive signaling data from WebSocket
    async def receive(self, text_data):
        data = json.loads(text_data)

        # Broadcast signaling data to the other peer in the room
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'signaling_message',
                'data': data,
            }
        )

    # Send signaling data to WebSocket
    async def signaling_message(self, event):
        data = event['data']

        # Send signaling data to WebSocket
        await self.send(text_data=json.dumps(data))