from django.db import models

class auth_user(models.Model):
    username = models.CharField(max_length=150)
    email = models.CharField(max_length=254)

    def __str__(self):
        return self.email