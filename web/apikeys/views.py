from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from editprofile.imgUser import imgUser
from apikeys.config import amassConfig, ReconConfig, GithubConfig
# Create your views here.

otherNames = {'passivedns': '360PassiveDNS', 'digicert': 'CertCentral', 'psbdmp':'Pastebin', 'rikiq':'PassiveTotal', 'quake360':'quake', 'cisco':'Umbrella', 'leaklookup_priv':'leak-lookup_priv', 'leaklookup_pub':'leak-lookup_pub'}

@login_required(login_url='/login/')
def conf(request):
    keys = dict(request.POST)
    del keys["csrfmiddlewaretoken"]
    if 'UserPicture' in keys:
        del keys['UserPicture']

    if keys["type"][0] == "amass":
        del keys["type"]

        for key in keys:
            name = key
            key = key=keys[key][0]
            if name in otherNames:
                name = otherNames[name]
            
            amassConfig(name, key=key)


    elif keys["type"][0] == "reconftw":
        del keys["type"]

        for key in keys:
            name = key
            key = key=keys[key][0]  
            ReconConfig(name, key=key)


    elif keys["type"][0] == "github":
        del keys["type"]

        for key in keys:
            number = int(key[-1])
            key = key=keys[key][0]  
            GithubConfig(number, key=key)


#    elif keys["type"][0] == "TheHarvester":
#        del keys["type"]
#
#        for key in keys:
#            name = key
#            key = key=keys[key][0]  
#            if name != "spyse":
#                theHarvesterConfig(name, key=key)

@login_required(login_url='/login/')
def index(request):

    if request.method == "POST":
        conf(request)

    imagePath = imgUser(request.user.id)

    context = {
                'shodan_value': ReconConfig('shodan', get=True),
        'whoisxml_value': ReconConfig('whoisxml', get=True),
        'xss_server_value': ReconConfig('xssserver', get=True),
        'collab_server_value': ReconConfig('collabserver', get=True),
        'slack_channel_value': ReconConfig('slackchanel', get=True),
        'slack_auth_value': ReconConfig('slackauth', get=True),

        'passivedns_value': amassConfig("360PassiveDNS", get=True),
        'asnlookup_value': amassConfig("asnlookup", get=True),
        'ahrefs_value': amassConfig("ahrefs", get=True),
        'alienvault_value': amassConfig("alienvault", get=True),
        'bevigil_value': amassConfig("bevigil", get=True),
        'bigdatacloud_value': amassConfig("bigdatacloud", get=True),
        'bufferover_value': amassConfig("bufferover", get=True),
        'builtwith_value': amassConfig("builtwith", get=True),
        'c99_value': amassConfig("c99", get=True),
        'censys_value': amassConfig("censys", get=True),
        'censysSecret_value': amassConfig("censysSecret", get=True),
        'chaos_value': amassConfig("chaos", get=True),
        'circlUsername_value': amassConfig("circlUsername", get=True),
        'circlPassword_value': amassConfig("circlPassword", get=True),
        'cloudflare_value': amassConfig("cloudflare", get=True),
        'digicert_value': amassConfig("CertCentral", get=True),
        'digicertUsername_value': amassConfig("digicertUsername", get=True),
        'dnsdb_value': amassConfig("dnsdb", get=True),
        'dnslytics_value': amassConfig("dnslytics", get=True),
        'dnsrepo_value': amassConfig("dnsrepo", get=True),
        'deepinfo_value': amassConfig("deepinfo", get=True),
        'detectify_value': amassConfig("detectify", get=True),
        'facebook_value': amassConfig("facebook", get=True),
        'facebookSecret_value': amassConfig("facebookSecret", get=True),
        'fofa_value': amassConfig("fofa", get=True),
        'fofaUsername_value': amassConfig("fofaUsername", get=True),
        'fullhunt_value': amassConfig("fullhunt", get=True),
        'github_value': amassConfig("github", get=True),
        'hackertarget_value': amassConfig("hackertarget", get=True),
        'hunter_value': amassConfig("hunter", get=True),
        'intelx_value': amassConfig("intelx", get=True),
        'ipdata_value': amassConfig("ipdata", get=True),
        'ipinfo_value': amassConfig("ipinfo", get=True),
        'leakix_value': amassConfig("leakix", get=True),
        'netlas_value': amassConfig("netlas", get=True),
        'networksdb_value': amassConfig("networksdb", get=True),
        'onyphe_value': amassConfig("onyphe", get=True),
        'psbdmp_value': amassConfig("Pastebin", get=True),
        'rikiq_value': amassConfig("PassiveTotal", get=True),
        'rikiqUsername_value': amassConfig("rikiqUsername", get=True),
        'pentesttools_value': amassConfig("pentesttools", get=True),
        'quake360_value': amassConfig("quake", get=True),
        'socradar_value': amassConfig("socradar", get=True),
        'securitytrails_value': amassConfig("SecurityTrails", get=True),
        'shodan2_value': amassConfig("shodan", get=True),
        'spamhausUsername_value': amassConfig("spamhausUsername", get=True),
        'spamhausPassword_value': amassConfig("spamhausPassword", get=True),
        'spyse_value': amassConfig("spyse", get=True),
        'threatbook_value': amassConfig("threatbook", get=True),
        'twitter_value': amassConfig("twitter", get=True),
        'twitterSecret_value': amassConfig("twitterSecret", get=True),
        'cisco_value': amassConfig("Umbrella", get=True),
        'urlscan_value': amassConfig("urlscan", get=True),
        'virustotal_value': amassConfig("virustotal", get=True),
        'whoisxmlapi_value': amassConfig("whoisxmlapi", get=True),
        'zetalytics_value': amassConfig("zetalytics", get=True),
        'zoomeyeUsername_value': amassConfig("zoomeyeUsername", get=True),
        'zoomeyePassword_value': amassConfig("zoomeyePassword", get=True),
        'yandex_value': amassConfig("yandex", get=True),
        'yandexUsername_value': amassConfig("yandexUsername", get=True),

        'token_1_value': GithubConfig('1', get=True),
        'token_2_value': GithubConfig('2', get=True),
        'token_3_value': GithubConfig('3', get=True),
        'token_4_value': GithubConfig('4', get=True),
        'token_5_value': GithubConfig('5', get=True),
        'token_6_value': GithubConfig('6', get=True),

        "imagePath": imagePath,
        "apikeys_settings": "API Keys Settings",
    }


    return render(request, "apikeys_settings.html", context)