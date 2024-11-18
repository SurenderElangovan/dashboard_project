from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomPersonalUser

class CustomUserAdmin(UserAdmin):
    model = CustomPersonalUser
    list_display = ('id', 'username', 'email', 'is_verified', 'is_paid')
    list_filter = ('is_verified', 'is_paid')

admin.site.register(CustomPersonalUser, CustomUserAdmin)
