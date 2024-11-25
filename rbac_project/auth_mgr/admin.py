from django.contrib import admin
from .models import OTAUser,OTP


@admin.register(OTAUser)
class OTAUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name' , 'last_name','is_active', 'ota_active', 'is_deleted')
    search_fields = ('username', 'email')

admin.site.register(OTP)