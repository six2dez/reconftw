import os
import time

def imgUser(id):

    imagePath = "static/imgUsers/img" + str(id) + ".png"

    if os.path.exists(imagePath) == False:
        imagePath = "/static/imgUsers/Defult.png"
    else:
        imagePath = "/" + imagePath + "?date="+str(time.time()).split(".")[0]

    return imagePath