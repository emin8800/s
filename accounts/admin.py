from .models import CustomUser
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active','telephone')
    search_fields = ('username', 'email')

    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('telephone',)}),  
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('telephone',)}), 
    )


admin.site.index_title = 'FeedSync'
admin.site.site_header = 'FeedSync AdminPanel'


