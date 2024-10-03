# accounts/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    last_logout = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username

    def update_last_login(self):
        self.last_login = timezone.now()
        self.save()

    def update_last_logout(self):
        self.last_logout = timezone.now()
        self.save()
