from django.contrib import admin
from .models import Doctors, Patient, Visit, Tooth, OrthoIndicator

@admin.register(Doctors)
class DoctorsAdmin(admin.ModelAdmin):
    list_display = ('last_name', 'first_name', 'phone', 'email', 'birth_date', 'created_at')
    search_fields = ('last_name', 'first_name', 'phone', 'email')

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    list_display = ('last_name', 'first_name', 'phone', 'email', 'birth_date', 'doctor')
    search_fields = ('last_name', 'first_name', 'phone', 'email')
    list_filter = ('doctor',)
    readonly_fields = ('created_at',)

@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ('patient', 'doctor', 'date')
    search_fields = ('patient__last_name', 'doctor__last_name')
    list_filter = ('date', 'doctor')

@admin.register(Tooth)
class ToothAdmin(admin.ModelAdmin):
    list_display = ('patient', 'number', 'enamel_color')
    search_fields = ('patient__last_name', 'number')
    list_filter = ('enamel_color',)

@admin.register(OrthoIndicator)
class OrthoIndicatorAdmin(admin.ModelAdmin):
    list_display = ('visit', 'indicator_name', 'value')
    search_fields = ('indicator_name', 'value')
    list_filter = ('indicator_name',)
