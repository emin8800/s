# import uuid
# from django.db import models
# from django.utils import timezone
# from django.contrib.auth.models import AbstractUser,BaseUserManager
# from django.contrib.auth.hashers import make_password



# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         """Kullanıcı oluşturma metodu."""
#         if not email:
#             raise ValueError('Bir e-posta adresi sağlamalısınız')
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, password=None, **extra_fields):
#         """Süper kullanıcı oluşturma metodu."""
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)

#         if extra_fields.get('is_staff') is not True:
#             raise ValueError('Süper kullanıcının is_staff olması gerekir.')
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError('Süper kullanıcının is_superuser olması gerekir.')

#         return self.create_user(email, password, **extra_fields)

# class CustomUser(AbstractUser):
#     uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
#     telephone = models.CharField(max_length=15, null=True, blank=True)
#     verification_code = models.IntegerField(null=True, blank=True)
#     last_logout = models.DateTimeField(null=True, blank=True)
#     is_verified = models.BooleanField(default=False)
#     email = models.EmailField(unique=True)
#     username = models.CharField(max_length=150, unique=False)
#     password_reset_sent_at = models.DateTimeField(null=True, blank=True)
    
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = []

#     objects = CustomUserManager()  # Kullanıcı yöneticisini tanımlayın

#     def __str__(self):
#         return self.email


#     def update_last_login(self):
#         self.last_login = timezone.now()
#         self.save()

#     def update_last_logout(self):
#         self.last_logout = timezone.now()
#         self.save()

#     def save(self, *args, **kwargs):
#         if self.password and not self.password.startswith('pbkdf2_sha256$'):
#             self.password = make_password(self.password)
#         super().save(*args, **kwargs)



import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.contrib.auth.hashers import make_password

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Bir e-posta adresi sağlamalısınız')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    uid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    telephone = models.CharField(max_length=15, null=True, blank=True)
    verification_code = models.IntegerField(null=True, blank=True)
    last_logout = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_2fa_enabled = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, null=True, blank=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=False)
    password_reset_sent_at = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
