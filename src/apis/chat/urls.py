from django.urls import path

from apis.chat import views as chat_views


app_name: str = "chat"

urlpatterns: list = [
    path('', chat_views.index, name='index'),
    path('<str:room_name>/', chat_views.room, name='room')
]
