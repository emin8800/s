from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password

class CustomUser(AbstractUser):
    telephone = models.CharField(max_length=15, null=True, blank=True)
    verification_code = models.IntegerField(null=True, blank=True)
    last_logout = models.DateTimeField(null=True, blank=True)
    username = models.CharField(max_length=150, unique=True)
    is_verified = models.BooleanField(default=False)
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.username

    def update_last_login(self):
        self.last_login = timezone.now()
        self.save()

    def update_last_logout(self):
        self.last_logout = timezone.now()
        self.save()

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
