from django.contrib.auth.admin import UserAdmin
from django.contrib import admin
from .models import *


admin.site.register(AdminProfile)
admin.site.register(Doctor)
admin.site.register(Patient)
admin.site.register(AppointmentSlot)
admin.site.register(Appointment)
admin.site.register(DiagnosticReport)
admin.site.register(Review)
admin.site.register(Prescription)
admin.site.register(Specialization)
admin.site.register(PatientProfile)
admin.site.register(Day)

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password', 'user_type', 'phone_number')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'user_type', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'first_name', 'last_name')