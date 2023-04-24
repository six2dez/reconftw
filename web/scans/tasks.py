
from django.utils import timezone
from django.core.files.base import ContentFile
from web.celery import app
from web.settings import BASE_DIR
from .models import *
from scans.utils import *
import favicon, requests, subprocess



@app.task(name='new_scan_single_domain')
def new_scan_single_domain(*command):
    """task that creates scan project"""
    command = str(command).split("'")
    del command[0::2]
    single_domain = command[2]

    # COUNTING PROJECTS OF SAME DOMAIN TO CALCULATE THE NEXT NUMBER
    if Project.objects.filter(domain=single_domain).exists():
        next = str(Project.objects.filter(domain=single_domain).count() + 1)
    else:
        next = "1"

    path = BASE_DIR.parent / f"Recon/{single_domain}_v{next}"

    command.append('-o') 
    command.append(str(path))
    

    match str(command[3]):
        case '-r': # RECON
            scan_mode = "[ -r ] - Recon"
            
        case '-s': # SUBDOMAINS
            scan_mode = "[ -s ] - Subdomains"

        case '-p': # PASSIVE
            scan_mode = "[ -p ] - Passive"

        case '-w': # WEB
            scan_mode = "[ -w ] - Web"
        
        case '-n': # OSINT
            scan_mode = "[ -n ] - Osint"
        
        case '-a': # ALL
            scan_mode = "[ -a ] - All"
        

    # ADDING DOMAIN
    puredomain = str(single_domain).split('.')[0]
    
    # SAVING PROJECT IN DB
    Project.objects.create(number=next,
                             domain=single_domain,
                             last_change=timezone.now(),
                             command=str(command),
                             scan_mode=scan_mode
                             )


    # GETTING THE ICON
    if not Project.objects.filter(icon = "static/img/target_icon/{}.ico".format(puredomain)).exists():
         try:
             target_icon = Project.objects.get(domain=single_domain, number=next)
             name_icon = "{}.ico".format(puredomain)
             icon_url = favicon.get('http://{}'.format(single_domain))
            
             if icon_url:
                 icon = icon_url[0]
                 print("ICON URL: "+str(icon))
 
                 response = requests.get(icon.url, stream=True, timeout=10)

                 if response.status_code  == 200:
                         target_icon.icon.save(name_icon, ContentFile(response.content), save=True)

         except Exception as err:
            print(err)
    
    # STARTING RUN_SCAN TASK
    r = run_scan.apply_async(args=[command, next], queue="run_scans")



@app.task(name='run_scan')
def run_scan(command, num):
    """task to run scan"""
    proj = Project.objects.filter(number=num, domain=command[2])[0]
    proj_id = proj.pk

    single_domain = command[2]
    monitor(single_domain)

    proj.status = 'SCANNING'
    proj.save()

    # RUNNING RECONFTW.SH
    p = subprocess.Popen(command).wait()

    print(p)

    f2db = files_to_db(command[3], proj_id)
    proj.status = 'FINISHED'
    proj.save()
   