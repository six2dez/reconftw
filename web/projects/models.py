from django.db import models

class Project(models.Model):
    number = models.PositiveSmallIntegerField(default=1)
    icon = models.ImageField(default=None, upload_to = 'static/img/target_icon')
    domain = models.CharField(max_length=300)
    last_change = models.DateTimeField(auto_now=False, blank=True,null=True,)
    STATUS_CHOICES = (("SCANNING", "Scanning"),("FINISHED", "Finished"),("WAITING","Waiting"))
    status = models.CharField(max_length=9, choices=STATUS_CHOICES, default='WAITING')
    command = models.CharField(max_length=400, unique=False, blank=True, null=True)
    scan_mode = models.CharField(max_length=400, unique=False, blank=True, null=True)

    def get_last_change(self):
        if self.last_change:
            return self.last_change.strftime('%d/%m/%Y - %H:%M')

        return self.last_change.strftime('%d/%m/%Y %H:%M')

    def __str__(self):
        return self.domain
    
    