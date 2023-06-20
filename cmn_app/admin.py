from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import UserProfile


class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'custom_hashed_password')

    def custom_hashed_password(self, obj):
        # Retrieve the custom hashed password from the user's profile
        custom_hashed_password = obj.userprofile.custom_hashed_password
        return custom_hashed_password

    custom_hashed_password.short_description = 'Custom Hashed Password'
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

