from re import search, compile, sub
from .models import *
from pathlib import Path
from os import listdir
from itertools import groupby
from ast import literal_eval
from base64 import b64encode
import json
import time


def monitor(domain):
    '''function to monitor scans statuses'''
    stop = False

    while stop != True:
        scans= Project.objects.filter(domain=domain)
        if scans.count() >= 1:
            allStatus = []

            for scan in scans:
                if scan.status == "SCANNING":
                    allStatus.append("SCANNING")
                else:
                    allStatus.append("FINISHED")

            if "SCANNING" not in allStatus:
                stop = True
            else:
                time.sleep(0.5)
        else:
            stop = True
        
        # print(stop)



# FUNCTIONS THAT SCRAP FILES AND SAVE TO THE DATABASE
def files_to_db(type_scan, project_id):
    """function to call files scrapers' functions and save to database"""
    print('[+] saving to db [+]')

    if type_scan == '-r': # RECON
        domaininfogeneral_f2db(project_id)
        domaininfoname_f2db(project_id)
        domaininfoemail_f2db(project_id)
        domaininfoip_f2db(project_id)
        emails_f2db(project_id)
        dorks_f2db(project_id)
        gitdorks_f2db(project_id)
        softwareinfo_f2db(project_id)
        authorsinfo_f2db(project_id)
        metadataresults_f2db(project_id)
        favicontest_f2db(project_id)
        subdomains_dns_f2db(project_id)
        subdomains_f2db(project_id)
        s3buckets_f2db(project_id)
        cloudasset_f2db(project_id)
        zonetransfer_f2db(project_id)
        subtakeover_f2db(project_id)
        webprobes_f2db(project_id)
        webfullinfo_uncommon_f2db(project_id)
        webs_uncommon_ports_f2db(project_id)
        webfullinfo_f2db(project_id)
        screenshots_f2db(project_id)
        portscanactive_f2db(project_id)
        portscanpassive_f2db(project_id)
        cdnproviders_f2db(project_id)
        webwafs_f2db(project_id)
        nucleioutputs_f2db(project_id)
        cms_f2db(project_id)
        fuzzingfull_f2db(project_id)
        urlextract_f2db(project_id)
        urlgf_f2db(project_id)
        jschecks_f2db(project_id)
        webdicts_f2db(project_id)

    elif type_scan == '-s': # SUBDOMAINS
        subdomains_dns_f2db(project_id)
        subdomains_f2db(project_id)
        s3buckets_f2db(project_id)
        cloudasset_f2db(project_id)
        zonetransfer_f2db(project_id)
        subtakeover_f2db(project_id)
        webprobes_f2db(project_id)
        webfullinfo_uncommon_f2db(project_id)
        webfullinfo_f2db(project_id)
        webs_uncommon_ports_f2db(project_id)
        screenshots_f2db(project_id)
        


    elif type_scan == '-p': # PASSIVE
        domaininfogeneral_f2db(project_id)
        domaininfoname_f2db(project_id)
        domaininfoemail_f2db(project_id)
        domaininfoip_f2db(project_id)
        emails_f2db(project_id)
        dorks_f2db(project_id)
        gitdorks_f2db(project_id)
        softwareinfo_f2db(project_id)
        authorsinfo_f2db(project_id)
        metadataresults_f2db(project_id)
        favicontest_f2db(project_id)
        subdomains_f2db(project_id)
        subdomains_dns_f2db(project_id)
        portscanpassive_f2db(project_id)
        cdnproviders_f2db(project_id)
        webfullinfo_f2db(project_id)

    
    
    elif type_scan == '-w': # WEB
        s3buckets_f2db(project_id)
        cloudasset_f2db(project_id)
        subtakeover_f2db(project_id)
        webwafs_f2db(project_id)
        nucleioutputs_f2db(project_id)
        cms_f2db(project_id)
        fuzzingfull_f2db(project_id)
        urlextract_f2db(project_id)
        urlgf_f2db(project_id)
        jschecks_f2db(project_id)
        webdicts_f2db(project_id)
        vulns_f2db(project_id)

    elif type_scan == '-n': # OSINT
        domaininfoemail_f2db(project_id)
        domaininfogeneral_f2db(project_id)
        domaininfoip_f2db(project_id)
        domaininfoname_f2db(project_id)
        ipsinfos_f2db(project_id)
        emails_f2db(project_id)
        dorks_f2db(project_id)
        gitdorks_f2db(project_id)
        metadataresults_f2db(project_id)
        zonetransfer_f2db(project_id)
        favicontest_f2db(project_id)

    elif type_scan == '-a': # ALL
        domaininfogeneral_f2db(project_id)
        domaininfoname_f2db(project_id)
        domaininfoemail_f2db(project_id)
        domaininfoip_f2db(project_id)
        emails_f2db(project_id)
        dorks_f2db(project_id)
        gitdorks_f2db(project_id)
        softwareinfo_f2db(project_id)
        authorsinfo_f2db(project_id)
        metadataresults_f2db(project_id)
        favicontest_f2db(project_id)
        subdomains_dns_f2db(project_id)
        subdomains_f2db(project_id)
        s3buckets_f2db(project_id)
        cloudasset_f2db(project_id)
        zonetransfer_f2db(project_id)
        subtakeover_f2db(project_id)
        webprobes_f2db(project_id)
        webs_uncommon_ports_f2db(project_id)
        webfullinfo_f2db(project_id)
        webfullinfo_uncommon_f2db(project_id)
        screenshots_f2db(project_id)
        portscanactive_f2db(project_id)
        portscanpassive_f2db(project_id)
        cdnproviders_f2db(project_id)
        webwafs_f2db(project_id)
        nucleioutputs_f2db(project_id)
        cms_f2db(project_id)
        fuzzingfull_f2db(project_id)
        urlextract_f2db(project_id)
        urlgf_f2db(project_id)
        jschecks_f2db(project_id)
        webdicts_f2db(project_id)
        vulns_f2db(project_id)
    
    print('[+] finished saving to db [+]')



def subdomains_dns_f2db(project_id):
    print("[+] subdomains_dns: saving to db [+]")
    subdomains_save = SubdomainsDNS.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/subdomains/subdomains_dnsregs.json"

    if Path(file_path).is_file():
        with open(file_path) as f:
            subs = f.readlines()
        
            for index, s in enumerate(subs):
                print(f"[+] saving {index} of {len(subs)}")
                j = json.loads(s.rstrip())
                subdomains_save.create(host=j['host'], 
                                        resolver=j['resolver'], 
                                        cname=j.get('cname', 'N/A'), 
                                        a_record=j.get('a', 'N/A'), 
                                        aaaa_record=j.get('aaaa', 'N/A'), 
                                        mx_record=j.get('mx', 'N/A'), 
                                        soa_record=j.get('soa', 'N/A'), 
                                        ns_record=j.get('ns', 'N/A'), 
                                        internal_ips_record=j.get('internal_ips', 'N/A'), 
                                        project_id=project_id
                                        )
    else:
        print("does not exist")
    print("[+] subdomains_dns: finished saving!! [+]")



def s3buckets_f2db(project_id):
    print("[+] s3buckets: saving to db [+]")
    s3buckets_save = S3Buckets.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/subdomains/s3buckets.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            s3 = f.readlines()
        
        for s in s3:
            if '|' in s:
                j = s.rstrip().split('|')
                s3buckets_save.create(url=j[0], 
                                        bucket_exists=(True if 'bucket_exists' in j[1] else False), 
                                        auth_users=j[2].split(',')[0].split(':')[1].lstrip(), 
                                        all_users=j[2].split(',')[1].split(':')[1].lstrip(), 
                                        project_id=project_id
                                        )
    print("[+] s3buckets: finished saving!! [+]")



def webfullinfo_f2db(project_id):
    print("[+] webfullinfo: saving to db [+]")
    webfullinfo_save = WebFullInfo.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/web_full_info.txt"

    filep = Path(file_path)

    if filep.is_file():

        filep.write_text(filep.read_text().replace('}\n{', '},{'))

        with open(file_path, 'r+') as f:
            content = f.read()
            f.seek(0)
            f.write('['+content)
            c2 = f.read()
            f.write(c2+']')

        f = open(file_path).read()
        wfi = json.loads(f)

        for w in wfi:
            webfullinfo_save.create(url=w.get('url', 'N/A').split('/')[2].split(':')[0],
                                    port=w.get('port', 'N/A'),
                                    technologies=w.get('technologies', 'N/A'),
                                    a=w.get('a', 'N/A'), 
                                    location=w.get('location', 'N/A'), 
                                    webserver=w.get('webserver', 'N/A'), 
                                    method=w.get('method', 'N/A'), 
                                    host_ip=w.get('host_ip', 'N/A'),  
                                    status_code=w.get('status-code', 'N/A'), 
                                    tls_grab=w.get('tls-grab', 'N/A'), 
                                    project_id=project_id
                                    )
    print("[+] webfullinfo: finished saving!! [+]")



def webfullinfo_uncommon_f2db(project_id):
    print("[+] webfullinfo_uncommon: saving to db [+]")
    webfullinfo_save = WebFullInfoUncommon.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/web_full_info_uncommon.txt"
    filep = Path(file_path)

    if filep.is_file():

        filep.write_text(filep.read_text().replace('}\n{', '},{'))

        with open(file_path, 'r+') as f:
            content = f.read()
            f.seek(0)
            f.write('['+content)
            c2 = f.read()
            f.write(c2+']')

        f = open(file_path).read()
        wfi = json.loads(f)

        for w in wfi:
            webfullinfo_save.create(url=w.get('url', 'N/A').split('/')[2].split(':')[0],
                                    port=w.get('port', 'N/A'),
                                    tech=w.get('tech', 'N/A'),
                                    ip=w.get('host', 'N/A'),
                                    project_id=project_id)
    print("[+] webfullinfo_uncommon: finished saving!! [+]")



def cloudasset_f2db(project_id):

    cloudasset_save = CloudAssets.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/subdomains/cloud_assets.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            ca = f.readlines()

        for i in ca:
            if 'Protected' in i:
                protected_s3 = i.split(': ')[-1].strip()
            else:
                protected_s3 = 'N/A'

            if 'App Found' in i:
                appfound = i.split(': ')[-1].strip()
            else:
                appfound = 'N/A'
            
            if 'Storage Account' in i:
                storage_acc = i.split(': ')[-1].strip()
            else:
                storage_acc = 'N/A'

            if 'Azure' in i:
                azure = i.split(': ')[-1].strip()
            else:
                azure = 'N/A'

            if 'Google' in i:
                google = i.split(': ')[-1].strip()
            else:
                google = 'N/A'


        cloudasset_save.create(protected_s3bucket=protected_s3, appfound=appfound, storage_account=storage_acc, azure=azure, google=google, project_id=project_id)
    


def domaininfoip_f2db(project_id):

    domaininfoip_save = DomainInfoIP.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/domain_info_ip.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            dip = f.read()

        domaininfoip_save.create(domain_info_ip=dip, project_id=project_id)



def portscanpassive_f2db(project_id):

    portscanpassive_save = PortscanPassive.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/hosts/portscan_passive.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            passive = f.readlines()

        d = []
        dc = {}
        for i in passive:
            if search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', i):
                if search(r"\(.*.\)", i):
                    l = i.split(' ')
                    dc['ip'] = l[0].rstrip()
                    dc['host'] = l[1].rstrip().strip('()')
                else:
                    dc['ip'] = i.rstrip()
                    dc['host'] = 'N/A'

            elif 'Ports' in i:
                dc['ports'] = i.strip().split(':')[1].split(', ')

            elif 'Tags' in i:
                dc['tags'] = i.strip().split(':')[1].strip()
            
            elif 'CPEs' in i:
                dc['cpes'] = (', '+i.strip().split('CPEs: ')[1]).split(', cpe:/a:')[1::]

            elif search(r'^\n', i):
                d.append(dc)
                dc = {}
            
        for j in d:
            portscanpassive_save.create(ip=j.get('ip', 'N/A'), 
                                        host=j.get('host', 'N/A'), 
                                        ports=j.get('ports', 'N/A'), 
                                        tags=j.get('tags', 'N/A'), 
                                        project_id=project_id
                                        )



def portscanactive_f2db(project_id):

    portscanactive_save = PortscanActive.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/hosts/portscan_active.gnmap"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            psa = f.readlines()

            for i in psa[1:-1:2]:
                addr = i.strip().split(': ')[1].split(' ')[0]
                status = i.strip().split(': ')[2]
                hostname = i.split(' (')[1].split(')')[0]
                openports = []
                for op in psa[psa.index(i)+1].split('\t')[1].split(': ')[1].split(', '):
                    openports.append(op.strip('/').split('//'))

                portscanactive_save.create(ip=addr, hostname=hostname, status=status, 
                                            openports=openports, project_id=project_id)
        


def dorks_f2db(project_id):

    dorks_save = Dorks.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
   
    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/dorks.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            dorks = f.read()

        dorks_save.create(dorks=dorks, project_id=project_id)
    


def gitdorks_f2db(project_id):

    gitdorks_save = GitDorks.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/gitdorks.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            gitdorks = f.read()

        gitdorks_save.create(git_dorks=gitdorks, project_id=project_id)



def fuzzingfull_f2db(project_id):

    fuzzingfull_save = FuzzingFull.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    file_path = f"{path[-1]}/{project_obj[0].domain}/fuzzing/fuzzing_full.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            fuzzinfull = f.readlines()

            fuzz_list = []

            for i in fuzzinfull[:-1:]:
                row = []
                row.append(i.split(' ')[0])
                row.append(i.split(' ')[1])
                row.append(i.split(' ')[2].strip())
                fuzz_list.append(row)
            
            fuzzingfull_save.create(fuzzing_full=fuzz_list, project_id=project_id)



def subdomains_f2db(project_id):

    subdomains_save = Subdomains.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/subdomains/subdomains.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            subdomains = f.read()

        subdomains_save.create(subdomains=subdomains, project_id=project_id)



def domaininfoname_f2db(project_id):

    domaininfo_name_save = DomainInfoName.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/domain_info_name.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            din = f.read()

        domaininfo_name_save.create(domain_info_name=din, project_id=project_id)



def domaininfogeneral_f2db(project_id):

    domaininfo_general_save = DomainInfoGeneral.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/domain_info_general.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            dig = f.read()

        domaininfo_general_save.create(domain_info_general=dig, project_id=project_id)



def domaininfoemail_f2db(project_id):

    domaininfo_email_save = DomainInfoEmail.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/domain_info_email.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            die = f.read()

        domaininfo_email_save.create(domain_info_email=die, project_id=project_id)



def emails_f2db(project_id):

    emails_save = Emails.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/emails.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            emails = f.read()

        emails_save.create(emails=emails, project_id=project_id)



def softwareinfo_f2db(project_id):

    softwareinfo_save = SoftwareInfo.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/software.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            soft = f.read()

        softwareinfo_save.create(software_info=soft, project_id=project_id)



def authorsinfo_f2db(project_id):

    authorsinfo_save = AuthorsInfo.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/authors.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            authors = f.read()

        authorsinfo_save.create(authors_info=authors, project_id=project_id)




def metadataresults_f2db(project_id):

    metadataresults_save = MetadataResults.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/metadata_result.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            metadata = f.read()

        metadataresults_save.create(metadata_results=metadata, project_id=project_id)



def zonetransfer_f2db(project_id):

    zonetransfer_save = Zonetransfer.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/subdomains/zonetransfer.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            zt = f.read()

        zonetransfer_save.create(zonetransfer=zt, project_id=project_id)



def favicontest_f2db(project_id):

    favicontest_save = Favicontest.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    file_path = f"{path[-1]}/{project_obj[0].domain}/hosts/favicontest.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            favicontest = f.read()

        favicontest_save.create(favicontest=favicontest, project_id=project_id)



def subtakeover_f2db(project_id):

    subtakeover_save = SubTakeover.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/takeover.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            subtakeover = f.readlines()
        
        for s in subtakeover:
            type_takeover = s.split('] ')[1].strip('[')
            subdomain = s.split('] ')[-1]
            subtakeover_save.create(type_takeover=type_takeover, subdomain=subdomain, project_id=project_id)



def screenshots_f2db(project_id):

    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    ss_path = f"{path[-1]}/{project_obj[0].domain}/screenshots"

    if Path(ss_path).is_dir() and len(listdir(ss_path)) > 0:
        ss_list = listdir(ss_path)

        for s in ss_list:
            with open(f"{ss_path}/{s}", 'rb') as f:
                img = f.read()

            hn = sub(r'https?-', '',s.replace('.png',''))

            i = hn.rfind('-')

            if '-' in hn and i > 0 and hn[i+1::].isnumeric():
                hn = f"{hn[:i:]}:{hn[i+1::]}"

            ScreenShots.objects.create(hostname=hn, screenshot=img, project_id=project_id)



def webprobes_f2db(project_id):

    webprobes_save = WebProbes.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/webs.txt"

    if Path(file_path).is_file():
        with open(file_path) as f:
            webs = f.read()

        webprobes_save.create(webprobes=webs, project_id=project_id)



def webwafs_f2db(project_id):

    webwafs_save = WebProbes.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/web_wafs.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            webwafs = f.read()

        webwafs_save.create(webwafs=webwafs, project_id=project_id)



def nucleioutputs_f2db(project_id):

    nucleioutputs_save = NucleiOutputs.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    nuclei_path = f"{path[-1]}/{project_obj[0].domain}/nuclei_output"

    if Path(nuclei_path).is_dir() and len(listdir(nuclei_path)) > 0:

        ld = listdir(nuclei_path)

        severities = ['info','low','medium','high','critical']

        j = {}

        for s in severities:
            sev_list = []
            if f'{s}.txt' in ld:
                with open (f"{nuclei_path}/{s}.txt") as f:
                    raw_list = f.readlines()

                    for i in raw_list:
                        sev_list.append(sub(r'\[', '', i.strip()).split(']'))
            else:
                sev_list.append('N/A')
            
            j[f'{s}'] = sev_list

        nucleioutputs_save.create(info=j.get('info', 'N/A'), low=j.get('low', 'N/A'), 
                                    medium=j.get('medium', 'N/A'), high=j.get('high', 'N/A'), 
                                    critical=j.get('critical', 'N/A'), project_id=project_id)



def urlgf_f2db(project_id):

    urlgf_save = URLgf.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    gf_path = f"{path[-1]}/{project_obj[0].domain}/gf"

    if Path(gf_path).is_dir() and len(listdir(gf_path)) > 0:

        ld = listdir(gf_path)
    
        if 'xss.txt' in ld:
            with open(f"{gf_path}/xss.txt") as f:
                xss = f.readlines()
                f.close()
        else:
            xss = 'N/A'
        
        if 'ssti.txt' in ld:
            with open(f"{gf_path}/ssti.txt") as f:
                ssti = f.readlines()
                f.close()
        else:
            ssti = 'N/A'
        
        if 'ssrf.txt' in ld:
            with open(f"{gf_path}/ssrf.txt") as f:
                ssrf = f.readlines()
                f.close()
        else:
            ssrf = 'N/A'
        
        if 'sqli.txt' in ld:
            with open(f"{gf_path}/sqli.txt") as f:
                sqli = f.readlines()
                f.close()
        else:
            sqli = 'N/A'
        
        if 'redirect.txt' in ld:
            with open(f"{gf_path}/redirect.txt") as f:
                redirect = f.readlines()
                f.close()
        else:
            redirect = 'N/A'

        if 'rce.txt' in ld:
            with open(f"{gf_path}/rce.txt") as f:
                rce = f.readlines()
                f.close()
        else:
            rce = 'N/A'

        if 'potential.txt' in ld:
            with open(f"{gf_path}/potential.txt") as f:
                potential = f.readlines()
                f.close()
        else:
            potential = 'N/A'

        if 'endpoints.txt' in ld:
            with open(f"{gf_path}/endpoints.txt") as f:
                endpoints = f.readlines()
                f.close()
        else:
            endpoints = 'N/A'

        if 'lfi.txt' in ld:
            with open(f"{gf_path}/lfi.txt") as f:
                lfi = f.read()
                f.close()
        else:
            lfi = 'N/A'
    else:
        xss = ssti = ssrf = sqli = redirect = rce = potential = endpoints = lfi = 'N/A'
    
    urlgf_save.create(xss=xss, ssti=ssti, ssrf=ssrf, sqli=sqli, 
                            redirect=redirect, rce=rce, potential=potential, endpoints=endpoints, 
                            lfi=lfi, project_id=project_id)



def vulns_f2db(project_id):

    vulns_save = Vulns.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    vulns_path = f"{path[-1]}/{project_obj[0].domain}/vulns"

    if Path(vulns_path).is_dir() and len(listdir(vulns_path)) > 0:

        ld = listdir(vulns_path)

        if 'brokenLinks.txt' in ld:
            with open(f"{vulns_path}/brokenLinks.txt") as f:
                brokenlinks = [x[:-1] for x in f.readlines()[:-1:]]
                f.close()
        else:
            brokenlinks = 'N/A'        
    
        if 'xss.txt' in ld:
            with open(f"{vulns_path}/xss.txt") as f:
                xss = f.read()
                f.close()
        else:
            xss = 'N/A'

        if 'cors.txt' in ld:
            with open(f"{vulns_path}/cors.txt") as f:
                cors = f.read()
        else:
            cors = 'N/A'
        
        if 'redirect.txt' in ld:
            with open(f"{vulns_path}/redirect.txt") as f:
                redirect = f.read()
                f.close()
        else:
            redirect = 'N/A'

        if 'ssrf_requested_url.txt' in ld:
            with open(f"{vulns_path}/ssrf_requested_url.txt") as f:
                ssrf_requested_url = f.read()
                f.close()
        else:
            ssrf_requested_url = 'N/A'

        if 'ssrf_requested_headers.txt' in ld:
            with open(f"{vulns_path}/ssrf_requested_headers.txt") as f:
                ssrf_requested_headers = f.read()
                f.close()
        else:
            ssrf_requested_headers = 'N/A'

        if 'ssrf_callback.txt' in ld:
            with open(f"{vulns_path}/ssrf_callback.txt") as f:
                ssrf_callback = f.read()
                f.close()
        else:
            ssrf_callback = 'N/A'

        if 'crlf.txt' in ld:
            with open(f"{vulns_path}/crlf.txt") as f:
                crlf = f.read()
                f.close()
        else:
            crlf = 'N/A'

        if 'lfi.txt' in ld:
            with open(f"{vulns_path}/lfi.txt") as f:
                lfi = f.read()
                f.close()
        else:
            lfi = 'N/A'

        if 'ssti.txt' in ld:
            with open(f"{vulns_path}/ssti.txt") as f:
                ssti = f.read()
                f.close()
        else:
            ssti = 'N/A'
        
        if 'testssl.txt' in ld:
            with open(f"{vulns_path}/testssl.txt") as f:
                testssl = f.read()
                f.close()
        else:
            testssl = 'N/A'

        if 'command_injection.txt' in ld:
            with open(f"{vulns_path}/command_injection.txt") as f:
                rcommand_injectionce = f.read()
                f.close()
        else:
            command_injection = 'N/A'

        if 'prototype_pollution.txt' in ld:
            with open(f"{vulns_path}/prototype_pollution.txt") as f:
                prototype_pollution = f.read()
                f.close()
        else:
            prototype_pollution = 'N/A'

        if 'smuggling.txt' in ld:
            with open(f"{vulns_path}/smuggling.txt") as f:

                urls = {'method': '', 'endpoint': '', 'cookies': ''}

                url = ''

                for line in f.readlines():
                    if "[+] url" in line.lower():
                        url = line.split(":", 1)[-1].replace("\n", "").replace(" ", "")
                        urls[url] ={}

                    
                    if "[+] method" in line.lower():
                        urls['method'] = line.split(":", 1)[-1].replace("\n", "").replace(" ", "")

                    if "[+] endpoint" in line.lower():
                        urls['endpoint'] = line.split(":", 1)[-1].replace("\n", "").replace(" ", "")

                        
                    if "[+] cookies" in line.lower():
                        urls['cookies'] = line.split(":", 1)[-1].replace("\n", "").replace(" ", "")


                    elif " ok " in line.lower() or "DISCONNECTED".lower() in line.lower():
                        if line.replace(" ", "") != "":
                            var = line.split(" ")[0].replace(":", "").replace("[", "").replace("]", "").replace("\n", "")
                            urls[url][var] = line.split(":", 1)[-1].replace(" ", "", 1).replace("\n", "")


                smuggling = str(json.dumps(urls))

                f.close()
        else:
            smuggling = 'N/A'

        if 'webcache.txt' in ld:
            with open(f"{vulns_path}/webcache.txt") as f:
                webcache = f.read()
                f.close()
        else:
            webcache = 'N/A'


        vulns_save.create(brokenlinks=brokenlinks, xss=xss, cors=cors, redirect=redirect, 
                            ssrf_requested_url=ssrf_requested_url, ssrf_requested_headers=ssrf_requested_headers,
                            ssrf_callback=ssrf_callback, crlf=crlf, lfi=lfi, ssti=ssti, testssl=testssl, 
                            command_injection=command_injection, prototype_pollution=prototype_pollution, 
                            smuggling=smuggling, webcache=webcache, project_id=project_id)



def webs_uncommon_ports_f2db(project_id):

    webs_unc_p_save = WebsUncommonPorts.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/webs_uncommon_ports.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            wup = f.readlines()
        
        w = []
        for i in wup[:-1:]:
            w.append(sub(r'https?:\/\/', '', i.strip()))
        
        w.sort()
        keyf = lambda text: text.split(":")[0]
        sorted_list = [list(items) for gr, items in groupby(sorted(w), key=keyf)]

        for s in sorted_list:
            ports = []
            for sn in s:
                ports.append(sn.split(':')[1])
            
            host = s[0].split(':')[0]
            webs_unc_p_save.create(host=host, ports=ports, project_id=project_id)



def webdicts_f2db(project_id):

    webdicts_save = WebDicts.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    webdicts_path = f"{path[-1]}/{project_obj[0].domain}/webs"

    if Path(webdicts_path).is_dir() and len(listdir(webdicts_path)) > 0:

        ld = listdir(webdicts_path)
    
        if 'dict_params.txt' in ld:
            with open(f"{webdicts_path}/dict_params.txt") as f:
                dict_params = [x[:-1] for x in f.readlines()]
                f.close()
        else:
            dict_params = ['N/A']
        
        if 'dict_values.txt' in ld:
            with open(f"{webdicts_path}/dict_values.txt") as f:
                dict_values = [x[:-1] for x in f.readlines()]
                f.close()
        else:
            dict_values = ['N/A']
        
        if 'dict_words.txt' in ld:
            with open(f"{webdicts_path}/dict_words.txt") as f:
                dict_words = [x[:-1] for x in f.readlines()]
                f.close()
        else:
            dict_words = ['N/A']
        
        if 'all_paths.txt' in ld:
            with open(f"{webdicts_path}/all_paths.txt") as f:
                all_paths = [x[:-1] for x in f.readlines()]
                f.close()
        else:
            all_paths = ['N/A']
        
        if 'password_dict.txt' in ld:
            with open(f"{webdicts_path}/password_dict.txt") as f:
                password_dict = f.read()
                f.close()
        else:
            password_dict = 'N/A'


        webdicts_save.create(dict_params=dict_params, dict_values=dict_values, dict_words=dict_words, 
                            all_paths=all_paths, password_dict=password_dict, project_id=project_id)



def urlextract_f2db(project_id):

    urlextract_save = URLExtract.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/url_extract.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            urle = f.read()

        urlextract_save.create(url_extract=urle, project_id=project_id)



def urlextract_f2db(project_id):

    urlextract_save = URLExtract.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/webs/url_extract.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            urle = f.read()

        urlextract_save.create(url_extract=urle, project_id=project_id)



def cdnproviders_f2db(project_id):

    cdnprov_save = CDNProviders.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/hosts/cdn_providers.txt"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            cdnp = f.read()

        cdnprov_save.create(cdn_providers=cdnp, project_id=project_id)



def jschecks_f2db(project_id):

    jschecks_save = JSChecks.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    jschecks_path = f"{path[-1]}/{project_obj[0].domain}/js"

    if Path(jschecks_path).is_dir() and len(listdir(jschecks_path)) > 0:

        ld = listdir(jschecks_path)

        files = ['js_livelinks','url_extract_js','js_endpoints','js_secrets']

        j = {}

        for s in files:
            js_list = []
            if f'{s}.txt' in ld:
                with open (f"{jschecks_path}/{s}.txt") as f:
                    raw_list = f.readlines()
                    
                    if 'secrets' not in s:
                        for i in raw_list:
                            js_list.append(i.strip())
                    else:
                        for i in raw_list:
                            js_list.append(sub(r'\[', '', i.strip()).split('] '))
                        
            else:
                js_list.append('N/A')
            
            j[f'{s}'] = js_list


        jschecks_save.create(js_livelinks=j.get('js_livelinks','N/A'), url_extract_js=j.get('url_extract_js','N/A'), 
                            js_endpoints=j.get('js_endpoints','N/A'), js_secrets=j.get('js_secrets','N/A'), project_id=project_id)



def ipsinfos_f2db(project_id):

    ipsinfos_save = IPsInfos.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    ipsinfos_path = f"{path[-1]}/{project_obj[0].domain}/osint"

    c1 = compile(r'ip_.*._relations\.txt')
    c2 = compile(r'ip_.*.whois\.txt')
    c3 = compile(r'ip_.*._location\.txt')

    if Path(ipsinfos_path).is_dir() and len(listdir(ipsinfos_path)) > 0:

        ld = listdir(ipsinfos_path)
    
        if any(c1.search(i) for i in ld):
            with open(f"{ipsinfos_path}/ip_domain_relations.txt") as f:
                ip_domain_relations = f.read()
                f.close()
        else:
            ip_domain_relations = 'N/A'
        
        if any(c2.search(i) for i in ld):
            with open(f"{ipsinfos_path}/ip_domain_whois.txt") as f:
                ip_domain_whois = f.read()
                f.close()
        else:
            ip_domain_whois = 'N/A' 

        if any(c3.search(i) for i in ld):
            with open(f"{ipsinfos_path}/ip_domain_location.txt") as f:
                ip_domain_location = f.read()
                f.close()
        else:
            ip_domain_location = 'N/A' 

        ipsinfos_save.create(ip_domain_relations=ip_domain_relations, ip_domain_whois=ip_domain_whois, 
                            ip_domain_location=ip_domain_location, project_id=project_id)



def osintusersinfo_f2db(project_id):

    osintusers_save = OSINTUsersInfo.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]
    
    osintusers_path = f"{path[-1]}/{project_obj[0].domain}/js"

    if Path(osintusers_path).is_dir() and len(listdir(osintusers_path)) > 0:

        ld = listdir(osintusers_path)
    
        if 'emails.txt' in ld:
            with open(f"{osintusers_path}/emails.txt") as f:
                emails = f.read()
                f.close()
        else:
            emails = 'N/A'
        
        if 'users.txt' in ld:
            with open(f"{osintusers_path}/users.txt") as f:
                users = f.read()
                f.close()
        else:
            users = 'N/A'
        
        if 'h8mail.txt' in ld:
            with open(f"{osintusers_path}/h8mail.txt") as f:
                h8mail = f.read()
                f.close()
        else:
            h8mail = 'N/A'
        
        if 'passwords.txt' in ld:
            with open(f"{osintusers_path}/passwords.txt") as f:
                passwords = f.read()
                f.close()
        else:
            passwords = 'N/A'

        if 'employees.txt' in ld:
            with open(f"{osintusers_path}/employees.txt") as f:
                employees = f.read()
                f.close()
        else:
            employees = 'N/A'

        if 'linkedin.txt' in ld:
            with open(f"{osintusers_path}/linkedin.txt") as f:
                linkedin = f.read()
                f.close()
        else:
            linkedin = 'N/A'


        osintusers_save.create(emails=emails, users=users, h8mail=h8mail, 
                            passwords=passwords, employees=employees, 
                            linkedin=linkedin, project_id=project_id)



def githubsecrets_f2db(project_id):

    githubsecrets_save = GithubCompanySecrets.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    file_path = f"{path[-1]}/{project_obj[0].domain}/osint/github_company_secrets.json"
    
    if Path(file_path).is_file():
        with open(file_path) as f:
            ghs = f.read()

        githubsecrets_save.create(github_secrets=ghs, project_id=project_id)



def cms_f2db(project_id):

    cms_save = CMS.objects
    project_obj = Project.objects.filter(pk=project_id)

    path = project_obj[0].command.split("'")
    del path[0::2]

    cms_path = f"{path[-1]}/{project_obj[0].domain}/cms/"
    
    if Path(cms_path).is_dir() and len(listdir(cms_path)) > 0:
        cms_files = listdir(cms_path)

        for s in cms_files:
            with open(s) as f:
                cms = f.read()

            cms_save.create(subdomain=s, cms=cms, project_id=project_id)
        
    else:
        cms_save.create(subdomain='N/A', cms='N/A', project_id=project_id)



def subdomains_context(project_id):

    subs_context = []

    for s in SubdomainsDNS.objects.filter(project_id=project_id).order_by('host'):
        j = {}

        subd = s.host
        ipaddr = s.a_record
        ports = []
        if WebsUncommonPorts.objects.filter(project_id=project_id, host=subd).exists():
            ports += literal_eval(WebsUncommonPorts.objects.filter(project_id=project_id, host=subd).values('ports').get()['ports'])
        if WebFullInfo.objects.filter(project_id=project_id, url=subd).exists():
            ports.append(str(literal_eval(WebFullInfo.objects.filter(project_id=project_id, url=subd).values('port').first()['port'])))
        if SubTakeover.objects.filter(project_id=project_id, subdomain=subd).exists():
            subtakeover = SubTakeover.objects.filter(project_id=project_id, subdomain=subd).values('type_takeover').get()['type_takeover']
        else:
            subtakeover = 'NO'
        
        j['subdomain'] = subd
        j['ip_address'] = ipaddr
        j['ports'] = ports
        j['subtakeover'] = subtakeover

        subs_context.append(j)
    
    return subs_context



def screenshots_context(number):
    ss = []
    for i in ScreenShots.objects.filter(project_id=number):
        s = []  
        s.append(i.hostname)
        s.append(i.port)
        s.append(b64encode(i.screenshot).decode('utf-8'))
        if WebFullInfo.objects.filter(project_id=number, url=i.hostname, port=i.port).exists():
            s.append(literal_eval(WebFullInfo.objects.filter(project_id=number, url=i.hostname, port=i.port).values('technologies').get()['technologies'])[0])
        elif WebFullInfoUncommon.objects.filter(project_id=number, url=i.hostname, port=i.port).exists():
            s.append(literal_eval(WebFullInfoUncommon.objects.filter(project_id=number, url=i.hostname, port=i.port).values('tech').get()['tech'])[0])
        else:
            s.append('N/A')
        ss.append(s)
    
    return ss


def delete_results(project_id):
    SubdomainsDNS.objects.filter(project_id=project_id).delete()
    S3Buckets.objects.filter(project_id=project_id).delete()
    WebFullInfo.objects.filter(project_id=project_id).delete()
    CloudAssets.objects.filter(project_id=project_id).delete()
    PortscanActive.objects.filter(project_id=project_id).delete()
    PortscanPassive.objects.filter(project_id=project_id).delete()
    GitDorks.objects.filter(project_id=project_id).delete()
    Dorks.objects.filter(project_id=project_id).delete()
    FuzzingFull.objects.filter(project_id=project_id).delete()
    Subdomains.objects.filter(project_id=project_id).delete()
    DomainInfoEmail.objects.filter(project_id=project_id).delete()
    DomainInfoGeneral.objects.filter(project_id=project_id).delete()
    DomainInfoIP.objects.filter(project_id=project_id).delete()
    DomainInfoName.objects.filter(project_id=project_id).delete()
    Emails.objects.filter(project_id=project_id).delete()
    SoftwareInfo.objects.filter(project_id=project_id).delete()
    AuthorsInfo.objects.filter(project_id=project_id).delete()
    MetadataResults.objects.filter(project_id=project_id).delete()
    Zonetransfer.objects.filter(project_id=project_id).delete()
    Favicontest.objects.filter(project_id=project_id).delete()
    SubTakeover.objects.filter(project_id=project_id).delete()
    ScreenShots.objects.filter(project_id=project_id).delete()
    WebProbes.objects.filter(project_id=project_id).delete()
    WebFullInfoUncommon.objects.filter(project_id=project_id).delete()
    WebWafs.objects.filter(project_id=project_id).delete()
    NucleiOutputs.objects.filter(project_id=project_id).delete()
    URLgf.objects.filter(project_id=project_id).delete()
    Vulns.objects.filter(project_id=project_id).delete()
    WebsUncommonPorts.objects.filter(project_id=project_id).delete()
    WebDicts.objects.filter(project_id=project_id).delete()
    URLExtract.objects.filter(project_id=project_id).delete()
    CDNProviders.objects.filter(project_id=project_id).delete()
    JSChecks.objects.filter(project_id=project_id).delete()
    IPsInfos.objects.filter(project_id=project_id).delete()
    OSINTUsersInfo.objects.filter(project_id=project_id).delete()
    GithubCompanySecrets.objects.filter(project_id=project_id).delete()
    CMS.objects.filter(project_id=project_id).delete()