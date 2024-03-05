from django.shortcuts import render


def index(request):
    return render(request, template_name='index.html')


def room(request, room_name: str):
    context: dict = {
        'room_name': room_name,
        'title': room_name
    }
    return render(request, template_name='room.html', context=context)
