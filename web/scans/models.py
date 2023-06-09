from django.db import models
from projects.models import Project

class SubdomainsDNS(models.Model):
    host = models.CharField(max_length=100, blank=True)
    resolver = models.CharField(max_length=200)
    cname = models.CharField(max_length=200, blank=True, default="N/A")
    a_record = models.CharField(max_length=200, blank=True, default="N/A")
    aaaa_record = models.CharField(max_length=200, blank=True, default="N/A")
    mx_record = models.CharField(max_length=200, blank=True, default="N/A")
    soa_record = models.CharField(max_length=200, blank=True, default="N/A")
    ns_record = models.CharField(max_length=200, blank=True, default="N/A")
    internal_ips_record = models.CharField(max_length=200, blank=True, default="N/A")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    class Meta:
        verbose_name = "Subdomain_DNS"
        verbose_name_plural = "Subdomains_scans"
        db_table = "subdomain_dns"

    def __str__(self):
        return self.host


class S3Buckets(models.Model):
    url = models.CharField(max_length=60, blank=True)
    bucket_exists = models.BooleanField()
    auth_users = models.CharField(max_length=200, blank=True, default="N/A")
    all_users = models.CharField(max_length=200, blank=True, default="N/A")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    class Meta:
        verbose_name = "S3_Buckets"
        db_table = "s3_buckets"

    def __str__(self):
        return self.url



class WebFullInfo(models.Model):
    url = models.CharField(max_length=160, blank=True)
    port = models.CharField(max_length=100, blank=True)
    technologies = models.CharField(max_length=300, blank=True)
    a = models.CharField(max_length=700, blank=True, default="N/A")
    location = models.CharField(max_length=200, blank=True, default="N/A")
    webserver = models.CharField(max_length=200, blank=True, default="N/A")
    method = models.CharField(max_length=10, blank=True, default="N/A")
    host_ip = models.CharField(max_length=15, blank=True, default="N/A")
    status_code = models.CharField(max_length=3, blank=True, default="N/A")
    tls_grab = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    class Meta:
        verbose_name = "Web_Full_Info"
        db_table = "web_fullinfo"

    def __str__(self):
        return self.url


class CloudAssets(models.Model):
    protected_s3bucket = models.CharField(max_length=100, blank=True)
    appfound = models.CharField(max_length=100, blank=True)
    storage_account = models.CharField(max_length=100, blank=True)
    azure = models.CharField(max_length=100, blank=True)
    google = models.CharField(max_length=100, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.appfound



class PortscanPassive(models.Model):
    ip = models.CharField(max_length=20, blank=True, default="N/A")
    host = models.CharField(max_length=60, blank=True, default="N/A")
    ports = models.CharField(max_length=300, blank=True, default="N/A")
    tags = models.CharField(max_length=100, blank=True, default="N/A")
    portscan_passive = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.ip


class PortscanActive(models.Model):
    ip = models.CharField(max_length=20, blank=True, default="N/A")
    hostname = models.CharField(max_length=50, blank=True, default="N/A")
    status = models.CharField(max_length=10, blank=True, default="N/A")
    openports = models.TextField(blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    def __str__(self):
        return self.address


class GitDorks(models.Model):
    git_dorks = models.TextField(blank=True, default="N/A")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.keyword


class Dorks(models.Model):
    dorks = models.TextField(blank=True, default="N/A")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.keyword


class FuzzingFull(models.Model):
    fuzzing_full = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class Subdomains(models.Model):
    subdomains = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class DomainInfoIP(models.Model):
    domain_info_ip = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class DomainInfoName(models.Model):
    domain_info_name = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class DomainInfoGeneral(models.Model):
    domain_info_general = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class DomainInfoEmail(models.Model):
    domain_info_email = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class Emails(models.Model):
    emails = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain        


class SoftwareInfo(models.Model):
    software_info = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain        


class AuthorsInfo(models.Model):
    authors_info = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain    


class MetadataResults(models.Model):
    metadata_results = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain    


class Zonetransfer(models.Model):
    zonetransfer = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain    


class Favicontest(models.Model):
    favicontest = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain 


class SubTakeover(models.Model):
    type_takeover = models.CharField(max_length=100, blank=True, default='N/A')
    subdomain = models.CharField(max_length=100, blank=True, default='N/A')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class ScreenShots(models.Model):
    hostname = models.CharField(max_length=100, blank=True)
    port = models.CharField(max_length=10, blank=True)
    screenshot = models.BinaryField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class WebProbes(models.Model):
    webprobes = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class WebFullInfoUncommon(models.Model):
    url = models.CharField(max_length=100, blank=True, default='N/A')
    port = models.CharField(max_length=100, blank=True, default='N/A')
    tech = models.CharField(max_length=200, blank=True, default='N/A')
    ip = models.CharField(max_length=100, blank=True, default='N/A')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class WebWafs(models.Model):
    webwafs = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class NucleiOutputs(models.Model):
    info = models.TextField()
    low = models.TextField()
    medium = models.TextField()
    high = models.TextField()
    critical = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class URLgf(models.Model):
    xss = models.TextField()
    ssti = models.TextField()
    ssrf = models.TextField()
    sqli = models.TextField()
    redirect = models.TextField()
    rce = models.TextField()
    potential = models.TextField()
    endpoints = models.TextField()
    lfi = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class Vulns(models.Model):
    brokenlinks = models.TextField()
    xss = models.TextField()
    cors = models.TextField()
    redirect = models.TextField()
    ssrf_requested_url = models.TextField()
    ssrf_requested_headers = models.TextField()
    ssrf_callback = models.TextField()
    crlf = models.TextField()
    lfi = models.TextField()
    ssti = models.TextField()
    testssl = models.TextField()
    command_injection = models.TextField()
    prototype_pollution = models.TextField()
    smuggling = models.TextField()
    webcache = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class WebsUncommonPorts(models.Model):
    host = models.CharField(max_length=100, blank=True)
    ports = models.CharField(max_length=300, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class WebDicts(models.Model):
    dict_params = models.TextField()
    dict_values = models.TextField()
    dict_words = models.TextField()
    all_paths = models.TextField()
    password_dict = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class URLExtract(models.Model):
    url_extract = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class CDNProviders(models.Model):
    cdn_providers = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class JSChecks(models.Model):
    js_livelinks = models.TextField()
    url_extract_js = models.TextField()
    js_endpoints = models.TextField()
    js_secrets = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class IPsInfos(models.Model):
    ip_domain_relations = models.TextField()
    ip_domain_whois = models.TextField()
    ip_domain_location = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class OSINTUsersInfo(models.Model):
    emails = models.TextField()
    users = models.TextField()
    passwords = models.TextField()
    employees = models.TextField()
    linkedin = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class GithubCompanySecrets(models.Model):
    github_secrets = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain


class CMS(models.Model):
    subdomain = models.CharField(max_length=100, blank=True)
    cms = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    
    def __str__(self):
        return self.project.domain

