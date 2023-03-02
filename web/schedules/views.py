import json
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
import json
from django.http import HttpResponse
# Create your views here.
from web.settings import TIME_ZONE
import urllib
from pathlib import Path
from datetime import datetime

from projects.models import Project
from django_celery_beat.models import CrontabSchedule, PeriodicTask


def timezone():
    timezones = {'Etc/GMT+12': '(GMT-12:00) International Date Line West', 'Pacific/Midway': '(GMT-11:00) Midway Island, Samoa', 'Pacific/Honolulu': '(GMT-10:00) Hawaii', 'US/Alaska': '(GMT-09:00) Alaska', 'America/Los_Angeles': '(GMT-08:00) Pacific Time (US & Canada)', 'America/Tijuana': '(GMT-08:00) Tijuana, Baja California', 'US/Arizona': '(GMT-07:00) Arizona', 'America/Chihuahua': '(GMT-07:00) Chihuahua, La Paz, Mazatlan', 'US/Mountain': '(GMT-07:00) Mountain Time (US & Canada)', 'America/Managua': '(GMT-06:00) Central America', 'US/Central': '(GMT-06:00) Central Time (US & Canada)', 'America/Mexico_City': '(GMT-06:00) Guadalajara, Mexico City, Monterrey', 'Canada/Saskatchewan': '(GMT-06:00) Saskatchewan', 'America/Bogota': '(GMT-05:00) Bogota, Lima, Quito, Rio Branco', 'US/Eastern': '(GMT-05:00) Eastern Time (US & Canada)', 'US/East-Indiana': '(GMT-05:00) Indiana (East)', 'Canada/Atlantic': '(GMT-04:00) Atlantic Time (Canada)', 'America/Caracas': '(GMT-04:00) Caracas, La Paz', 'America/Manaus': '(GMT-04:00) Manaus', 'America/Santiago': '(GMT-04:00) Santiago', 'Canada/Newfoundland': '(GMT-03:30) Newfoundland', 'America/Sao_Paulo': '(GMT-03:00) Brasilia', 'America/Argentina/Buenos_Aires': '(GMT-03:00) Buenos Aires, Georgetown', 'America/Godthab': '(GMT-03:00) Greenland', 'America/Montevideo': '(GMT-03:00) Montevideo', 'America/Noronha': '(GMT-02:00) Mid-Atlantic', 'Atlantic/Cape_Verde': '(GMT-01:00) Cape Verde Is.', 'Atlantic/Azores': '(GMT-01:00) Azores', 'Africa/Casablanca': '(GMT+00:00) Casablanca, Monrovia, Reykjavik', 'Etc/Greenwich': '(GMT+00:00) Greenwich Mean Time : Dublin, Edinburgh, Lisbon, London', 'Europe/Amsterdam': '(GMT+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna', 'Europe/Belgrade': '(GMT+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague', 'Europe/Brussels': '(GMT+01:00) Brussels, Copenhagen, Madrid, Paris', 'Europe/Sarajevo': '(GMT+01:00) Sarajevo, Skopje, Warsaw, Zagreb', 'Africa/Lagos': '(GMT+01:00) West Central Africa', 'Asia/Amman': '(GMT+02:00) Amman', 'Europe/Athens': '(GMT+02:00) Athens, Bucharest, Istanbul', 'Asia/Beirut': '(GMT+02:00) Beirut', 'Africa/Cairo': '(GMT+02:00) Cairo', 'Africa/Harare': '(GMT+02:00) Harare, Pretoria', 'Europe/Helsinki': '(GMT+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius', 'Asia/Jerusalem': '(GMT+02:00) Jerusalem', 'Europe/Minsk': '(GMT+02:00) Minsk', 'Africa/Windhoek': '(GMT+02:00) Windhoek', 'Asia/Kuwait': '(GMT+03:00) Kuwait, Riyadh, Baghdad', 'Europe/Moscow': '(GMT+03:00) Moscow, St. Petersburg, Volgograd', 'Africa/Nairobi': '(GMT+03:00) Nairobi', 'Asia/Tbilisi': '(GMT+03:00) Tbilisi', 'Asia/Tehran': '(GMT+03:30) Tehran', 'Asia/Muscat': '(GMT+04:00) Abu Dhabi, Muscat', 'Asia/Baku': '(GMT+04:00) Baku', 'Asia/Yerevan': '(GMT+04:00) Yerevan', 'Asia/Kabul': '(GMT+04:30) Kabul', 'Asia/Yekaterinburg': '(GMT+05:00) Yekaterinburg', 'Asia/Karachi': '(GMT+05:00) Islamabad, Karachi, Tashkent', 'Asia/Calcutta': '(GMT+05:30) Sri Jayawardenapura', 'Asia/Katmandu': '(GMT+05:45) Kathmandu', 'Asia/Almaty': '(GMT+06:00) Almaty, Novosibirsk', 'Asia/Dhaka': '(GMT+06:00) Astana, Dhaka', 'Asia/Rangoon': '(GMT+06:30) Yangon (Rangoon)', 'Asia/Bangkok': '(GMT+07:00) Bangkok, Hanoi, Jakarta', 'Asia/Krasnoyarsk': '(GMT+07:00) Krasnoyarsk', 'Asia/Hong_Kong': '(GMT+08:00) Beijing, Chongqing, Hong Kong, Urumqi', 'Asia/Kuala_Lumpur': '(GMT+08:00) Kuala Lumpur, Singapore', 'Asia/Irkutsk': '(GMT+08:00) Irkutsk, Ulaan Bataar', 'Australia/Perth': '(GMT+08:00) Perth', 'Asia/Taipei': '(GMT+08:00) Taipei', 'Asia/Tokyo': '(GMT+09:00) Osaka, Sapporo, Tokyo', 'Asia/Seoul': '(GMT+09:00) Seoul', 'Asia/Yakutsk': '(GMT+09:00) Yakutsk', 'Australia/Adelaide': '(GMT+09:30) Adelaide', 'Australia/Darwin': '(GMT+09:30) Darwin', 'Australia/Brisbane': '(GMT+10:00) Brisbane', 'Australia/Canberra': '(GMT+10:00) Canberra, Melbourne, Sydney', 'Australia/Hobart': '(GMT+10:00) Hobart', 'Pacific/Guam': '(GMT+10:00) Guam, Port Moresby', 'Asia/Vladivostok': '(GMT+10:00) Vladivostok', 'Asia/Magadan': '(GMT+11:00) Magadan, Solomon Is., New Caledonia', 'Pacific/Auckland': '(GMT+12:00) Auckland, Wellington', 'Pacific/Fiji': '(GMT+12:00) Fiji, Kamchatka, Marshall Is.', 'Pacific/Tongatapu': "(GMT+13:00) Nuku'alofa"}

    response = []

    for item in timezones:
        if item == TIME_ZONE:
            response.append([urllib.parse.quote_plus(item), timezones[item], 'true'])
        else:
            response.append([urllib.parse.quote_plus(item), timezones[item], ''])
    
    return response


@login_required
def define_timezone(request):

    if request.method == "POST":
        post = request.POST
      
        file = Path('web/settings.py')
        file.write_text(file.read_text().replace(TIME_ZONE, post['timezone_offset'], 1))
        
    
    return redirect('projects:index')
    
@login_required
def schedule_scan(request):

    if request.method == "POST":
        
        post = request.POST

        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        daylist = ""

        for item in days:
            if item in post:
                daylist += item+", "

        daylist = daylist[:-2]

        
        id = post['id']
        hours = post["hours"] if post["hours"] != "" else "00"
        minutes = post["minutes"] if post["minutes"] != "" else "00"
        nome = Project.objects.get(id=id).domain
        command = Project.objects.get(id=id).command.split("'")
        del command[0::2]


        if len(daylist) != 0:
            schedule = CrontabSchedule.objects.create(
                hour=hours,
                minute=minutes,
                day_of_week=daylist
            ) 

            task = PeriodicTask.objects.create(
                name=id+"-"+str(datetime.now()),
                task='new_scan_single_domain',
                crontab=schedule,
                args=json.dumps(command)
            )

            task.enabled = True
            task.save()


    return redirect('projects:index')

@login_required
def getSchedules(request):

    reqid = request.POST["projectId"]

    get = PeriodicTask.objects.all()

    schedules = {}

    for item in get:
        if item.name != "":
            if item.name.split("-", 1)[0] == reqid:
                if item.id not in schedules:
                    schedules[item.id] = {}

                schedules[item.id]["name"] = item.name
                schedules[item.id]["contrabId"] = int(item.crontab_id)
                schedules[item.id]["hours"] = int(CrontabSchedule.objects.get(id=item.crontab_id).hour)
                schedules[item.id]["minutes"] = int(CrontabSchedule.objects.get(id=item.crontab_id).minute)
                schedules[item.id]["days"] = CrontabSchedule.objects.get(id=item.crontab_id).day_of_week.split(", ")

    print(schedules)

    return HttpResponse(json.dumps(schedules), content_type="application/json")

@login_required
def deleteSchedule(request):

    scheduleName = request.POST['schedule-name']
    crontabId = request.POST['crontab-id']

    PeriodicTask.objects.get(name=scheduleName).delete()
    CrontabSchedule.objects.get(id=crontabId).delete()

    return redirect('projects:index')

@login_required
def deleteScheduleFromId(request, id):

    get = PeriodicTask.objects.all()

    for item in get:
        if item.name != "":
            if item.name.split("-", 1)[0] == str(id):

                scheduleName = item.name
                crontabId = int(item.crontab_id)

                PeriodicTask.objects.get(name=scheduleName).delete()
                CrontabSchedule.objects.get(id=crontabId).delete()

    return redirect('projects:index')