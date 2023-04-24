from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.files.storage import FileSystemStorage
from .imgUser import imgUser
import os

def edit(request):
    response = "change made!"

    username = request.user
    dbUser = User.objects.get(username=username)

    post = request.POST


    if 'username' in post:
        if dbUser.username != post['username']:
            dbUser.username = post['username']



    if 'email' in post:
        if dbUser.email != post['email']:
            dbUser.email = post['email']




    if 'CurrentPassword' in post and 'NewPassword' in post and 'ConfirmPassword' in post:
        if post['CurrentPassword'] != "" and post['NewPassword'] != "" and post['ConfirmPassword'] != "":
            CurrentPassword = post['CurrentPassword']

            if dbUser.check_password(CurrentPassword):
                if post['NewPassword'] == post['ConfirmPassword']:
                    dbUser.set_password(post['NewPassword'])
                else:
                    response = "new password and confirmation password are different!"
            else:
                response = "Current password wrong!"





    if 'UserPicture' in request.FILES:
        path = "static/imgUsers/img"+str(request.user.id)+".png"

        if os.path.exists(path):
            os.remove(path)

        myfile = request.FILES['UserPicture']
        fs = FileSystemStorage()
        filename = fs.save(path, myfile)



    if 'RemoveImg' in post:
        if post['RemoveImg'] == 'on':
            imagePath = "static/imgUsers/img" + str(dbUser.id) + ".png"

            if os.path.exists(imagePath):
                os.remove(imagePath)

            
        

    dbUser.save()
    

    return post['username'], response 


@login_required(login_url='/login/')
def index(request):

    


    if request.method == "POST":
        username, response = edit(request)
    
    else:
        username = request.user
        response = ""



    dbUser = User.objects.get(username=username)
    
    email = dbUser.email

    imagePath = imgUser(request.user.id)

    context = {
        "imagePath": imagePath,
        'UserName': username, 
        'email': email,
        'response': response,
        }
        
    return render(request, "edit_profile.html", context)