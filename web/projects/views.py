from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse
from projects.models import Project
from django.core.files.base import ContentFile
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from schedules.views import deleteScheduleFromId
from editprofile.imgUser import imgUser
from schedules.views import timezone
from web.settings import BASE_DIR
import shutil, os, time, requests, favicon
from pathlib import Path
from subprocess import Popen
import zipfile

# Main Projects Page
@login_required(login_url='/login/')
def index(request):

    imagePath = imgUser(request.user.id)

    timezones = timezone()

    projects_output = Project.objects.all()
    db_projects_count = Project.objects.values('domain').count()
    
    path = Path(__file__).resolve().parent.parent.parent / "Recon/"

    files_sorted_by_date = []
    final_date = []
    number_count = 0
    
    print("Path da pasta Recon: " + str(path))

    '''
    Case 'Recon' folder is not created, just load the page without any data.
    '''

    if not path.exists():
        context = {'projects_output':projects_output, "imagePath": imagePath, "timezones":timezones}
        return render(request, 'projects.html',context)
    elif path.exists():
        # Sort Archives by Creation Date
        archives_parsed = sorted(Path(path).iterdir(), key=os.path.getmtime)
        
        print(archives_parsed)

        for archives in archives_parsed:
            archives_by_date = str(archives).split('/')[-1]
            files_sorted_by_date.append(archives_by_date)
            print(files_sorted_by_date)

        # Get Domain and Creation Date
        if db_projects_count != int(len(files_sorted_by_date)):
            for i in range(len(files_sorted_by_date)):
                sgdomain = files_sorted_by_date[i]
                print("SGDOMAIN: "+str(sgdomain))

                ti_m = os.path.getmtime(path / sgdomain)
                m_ti = time.ctime(ti_m)
                t_obj = time.strptime(m_ti)
                T_stamp = time.strftime("%Y-%m-%d %H:%M:%S", t_obj)
            
                print("T_stamp: "+str(T_stamp))

                final_date.append(T_stamp)

                print("final_date: "+str(final_date))

                pjtfor = Project.objects.filter(domain=sgdomain)
                # print("pjt: "+str(pjtfor))


                # Save Domain
                for pjt in pjtfor:
                    if not projects_output.filter(domain=pjt, number=pjt.number).exists():
                        print("number_count: " +str(number_count))
                        # pjt.save()

                    # Creation Date    
                    if not projects_output.filter(last_change = final_date[i], number=pjt.number):    
                        # pjt.last_change = final_date[i]
                        print("SALVOU FINAL_DATE["+str(i)+"]: "+str(final_date[i]))
                        
                        # pjt.save()


                    # Number of Projects
                    project_count_obj = pjt
                    
                    print("project_count_obj: "+str(project_count_obj))
            
        
        # GET ICONS
            for i in range(len(files_sorted_by_date)):
                sgdomain = files_sorted_by_date[i]
                
                target_iconfor = Project.objects.filter(domain=sgdomain)
                for target_icon in target_iconfor:
                    puredomain = str(target_icon).split('.')[0]+str(target_icon.number)

                    name_icon = puredomain+".ico"
                    
                    if not Project.objects.filter(icon = "static/img/target_icon/"+puredomain+".ico", number=target_icon.number).exists():
                        try:
                            try:
                                icon_url = favicon.get('http://www.'+str(target_icon))
                                if not icon_url:
                                    target_icon.icon.name = 'static/img/unknown.ico'
                                    print("NAO EXISTE ICONE: " +str(puredomain))
                                    print()
                                    target_icon.save()
                                
                                else:
                                    icon = icon_url[0]
                                    print("ICON URL: "+str(icon_url))

                                    response = requests.get(icon.url, stream=True, timeout=10)



                                    if response.status_code  == 200:
                                        target_icon.icon.save(name_icon, ContentFile(response.content), save=True)
                                        print("SALVANDO ICONE: "+name_icon)
                                    else:
                                        target_icon.icon.name = 'static/img/unknown.ico'
                                        print("DIFERENTE DE 200: " +puredomain)
                                        target_icon.save()

                            except (requests.exceptions.ConnectionError,requests.exceptions.HTTPError): 
                                target_icon.icon.name = 'static/img/unknown.ico'
                                print("ERROR: " +puredomain)
                                target_icon.save()
                        except (requests.exceptions.ReadTimeout):
                            print(target_icon.icon.name)
                            
                    else:
                        print("ICON ALREADY EXISTS: "+ name_icon)
                print("----------------------------------------------------------------------")

            else:
                print("EVERYTHING UP")
        
        # Project Number
        for u in range(len(files_sorted_by_date)):
            sgdomain = files_sorted_by_date[u]
            number_count = number_count + 1

            project_count_objfor = Project.objects.filter(domain=sgdomain)
            
            for project_count_obj in project_count_objfor:
                project_count_obj.project_number = number_count
                project_count_obj.save()

                print("ID NUMBER: "+ str(project_count_obj.project_number)+" [DOMAIN]: "+str(project_count_obj))
            

        context = {'projects_output':projects_output, "imagePath": imagePath, "timezones":timezones}


        return render(request, 'projects.html',context)


# Delete Projects Function
@login_required(login_url='/login/')
def delete_project(request, id):
    if request.method == "POST":
        project = get_object_or_404(Project, id=id)
        puredomain = str(project.icon).split('.')[0]

        command = str(project.command).split("'")
        del command[0::2]
        
        if project.status != 'FINISHED':
            cancel_scan(request, id)

        if os.path.exists(command[-1]):
            path_projects_delete = command[-1]
        elif os.path.exists(f"{BASE_DIR.parent}/Recon/{str(project)}"):
            path_projects_delete = f"{BASE_DIR.parent}/Recon/{str(project)}"
        else:
            path_projects_delete = "xxx"

        path_icon_delete = str(puredomain)+".ico"

        try:
            shutil.rmtree(path_projects_delete, ignore_errors=True)
            os.remove(path_icon_delete)
            print(path_icon_delete)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

        Project.objects.filter(id=id).delete()
        deleteScheduleFromId(request, id=id)

        return redirect('projects:index')

@login_required(login_url='/login/')
def DownloadBackup(requests, id):

    project = Project.objects.get(id=id)
    if project.status == "FINISHED":
        command = str(project.command).split("'")
        del command[0::2]

        tempFolder = "/tmp"
        folderPath = command[-1].rsplit("/",1)[0]
        folderName = command[-1].rsplit("/",1)[1]

        if "/" in folderName:
            tmp = folderName.rsplit("/", 1)

            folderPath = tmp[0]
            folderName = tmp[1]

        if os.path.exists(tempFolder+"/Backup-"+folderName+".zip"):
            os.remove(tempFolder+"/Backup-"+folderName+".zip")

        os.chdir(folderPath)
        with zipfile.ZipFile(tempFolder+"/Backup-"+folderName+".zip", "w") as zf:
            for item in Path(folderName).rglob("*"):
                zf.write(item)
            zf.close()

        backupFileName = "Backup-"+folderName+".zip"

        file = open(tempFolder+"/"+backupFileName, "rb")

        response = HttpResponse(file, content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+backupFileName
        return response
    else:
        return HttpResponse('Scanning is not completed, please wait.')

# TODO: Cancel Scan Function 
@login_required(login_url='/login/')
def cancel_scan(request, id):
    if request.method == "POST":
        project = Project.objects.get(id=id)
        domain = project.domain

        cancel_cmd = ['pkill', '-f']
        
        Popen(cancel_cmd+[str(domain)]).wait()

        Popen(cancel_cmd+['/Tools/']).wait()

        return redirect('projects:index')
