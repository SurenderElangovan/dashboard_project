from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomPersonalUser(AbstractUser):
    email = models.EmailField(unique=True)
    profile_picture = models.ImageField(upload_to='profiles/', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_paid = models.BooleanField(default=False)
    password_reset_token = models.TextField(default=False,null=True,blank=True)