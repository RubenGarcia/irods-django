from django.db import models

# Create your models here.

# users/models.py
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    pass
    # add additional fields in here
    irods_username = models.CharField(max_length=30)

    REQUIRED_FIELDS = [irods_username]
    
    def __str__(self):
        return self.username
