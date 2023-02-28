from django.test import TestCase
from scans.tasks import *
from projects.models import Project
from scans.models import *
from time import sleep
from web.settings import BASE_DIR
import os

class TestCase(TestCase):
    def setUp(self):
        Project.objects.create(number=3, domain='target.com.br', last_change=timezone.now(), command='')
        Project.objects.create(number=4, domain='target.com.br', 
                                last_change=timezone.now(), 
                                command="('../reconftw', '-d','target.com.br', '-s', '-o', '/home/ubuntu/reconftw-hakai/Recon/target.com.br_v2')")
        print('#######################')

    def test(self):
        # print('aaaaaaaaaaaa')
        # pobj = Project.objects.filter(domain='target.com.br')[0]
        # print(f"==> PK: {pobj.number}")
        # # print(pobj[0].id)
        # # d = pobj[0].id
        # c = pobj.command.split("'")
        # del c[0::2]
        # print(f"{c[-1]}/{pobj.domain}")

        # celery_task = subdomains_dns_f2db.delay(pobj.pk)

        # sleep(10)

        # sub_scan = SubdomainsDNS.objects.filter(pk=pobj.pk)
        # print(sub_scan)

        l = os.listdir(f"{BASE_DIR.parent}/Recon/target.com.br/subdomains")
        if 'subdomains.txt' in l:
            print("has file")


