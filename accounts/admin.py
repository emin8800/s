from .models import CustomUser
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin



# @admin.register(CustomUser)
# class CustomUserAdmin(admin.ModelAdmin):
#     list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active','telephone','uid')
#     search_fields = ('username', 'email')

#     fieldsets = UserAdmin.fieldsets + (
#         (None, {'fields': ('telephone',)}),  
#     )

#     add_fieldsets = UserAdmin.add_fieldsets + (
#         (None, {'fields': ('telephone',)}), 
#     )
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'is_verified', 'is_2fa_enabled', 'last_login', 'last_logout')
    list_filter = ('is_verified', 'is_2fa_enabled')
    ordering = ('email',)
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('telephone', 'verification_code', 'is_verified', 'is_2fa_enabled')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('telephone', 'is_verified', 'is_2fa_enabled')}),
    )

admin.site.register(CustomUser, CustomUserAdmin)



admin.site.index_title = 'FeedSync'
admin.site.site_header = 'FeedSync AdminPanel'

