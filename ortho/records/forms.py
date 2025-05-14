from django import forms
from .models import *

class PatientForm(forms.ModelForm):
    class Meta:
        model = Patient
        fields = ['first_name', 'last_name', 'birth_date', 'phone', 'email', 'doctor', 'photo']



class VisitForm(forms.ModelForm):
    class Meta:
        model = Visit
        fields = ['patient', 'doctor', 'date', 'notes']


class ToothForm(forms.ModelForm):
    class Meta:
        model = Tooth
        fields = ['patient', 'number', 'enamel_color', 'notes']

class OrthoIndicatorForm(forms.ModelForm):
    class Meta:
        model = OrthoIndicator
        fields = ['visit', 'indicator_name', 'value']

class DoctorsForm(forms.ModelForm):
    class Meta:
        model = Doctors
        fields = ['first_name', 'last_name', 'birth_date', 'phone', 'email']