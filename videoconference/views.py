from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

# Create your views here.


@login_required
def dashboard(request):
    return render(request, 'videoconference/dashboard.html', {'name': request.user.first_name})

@login_required
def videocall(request):
    roomID = request.user.username
    print(roomID)
    return render(request, 'videoconference/videocall.html', {'name': request.user.first_name + " " + request.user.last_name, "roomID":1234})



@login_required
def join_room(request):
    if request.method == 'POST':
        roomID = request.POST['roomID']
        return redirect("/meeting?roomID=" + roomID)
    return render(request, 'videoconference/joinroom.html')
