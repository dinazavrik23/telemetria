from django.db import models
from django.utils import timezone

class Doctors(models.Model):
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    birth_date = models.DateField(default=timezone.now)
    phone = models.CharField(max_length=15, blank=True)
    email = models.EmailField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.last_name} {self.first_name}'

class Patient(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    birth_date = models.DateField()
    phone = models.CharField(max_length=15, blank=True)
    email = models.EmailField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    doctor = models.ForeignKey(Doctors, on_delete=models.CASCADE, null=True)

    # Добавляем поле для фото
    photo = models.ImageField(upload_to='patient_photos/', blank=True, null=True)

    def __str__(self):
        return f'{self.last_name} {self.first_name}'

class Visit(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctors, on_delete=models.CASCADE, null=True)
    date = models.DateField()
    notes = models.TextField(blank=True)

class Tooth(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    number = models.IntegerField()  # 1–32 например
    enamel_color = models.CharField(max_length=50)
    notes = models.TextField(blank=True)

class OrthoIndicator(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE)
    indicator_name = models.CharField(max_length=100)
    value = models.CharField(max_length=100)

