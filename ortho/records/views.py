from django.core.checks import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from records.models import *

from records.forms import *


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.Error(request, 'Неверное имя пользователя или пароль')
    return render(request, 'records/login.html')




@login_required

def dashboard(request):
    patients = Patient.objects.select_related('doctor')
    visits = Visit.objects.select_related('patient', 'doctor')
    teeth = Tooth.objects.select_related('patient')
    indicators = OrthoIndicator.objects.select_related('visit__patient')
    doctors = Doctors.objects.all()

    context = {
        'patients': patients,
        'visits': visits,
        'teeth': teeth,
        'indicators': indicators,
        'doctors': doctors
    }
    return render(request, 'records/dashboard.html', context)

def add_doctor(request):
    if request.method == 'POST':
        form = DoctorsForm(request.POST)
        if form.is_valid():
            form.save()
    return redirect('dashboard')

def add_patient(request):
    if request.method == 'POST':
        form = PatientForm(request.POST, request.FILES)
        #print(request.FILES)
        if form.is_valid():
            form.save()
    return redirect('dashboard')


def add_visit(request):
    if request.method == 'POST':
        form = VisitForm(request.POST)
        if form.is_valid():
            form.save()
    return redirect('dashboard')


def add_tooth(request):
    if request.method == 'POST':
        form = ToothForm(request.POST)
        if form.is_valid():
            form.save()
    return redirect('dashboard')


def add_indicator(request):
    if request.method == 'POST':
        form = OrthoIndicatorForm(request.POST)
        if form.is_valid():
            form.save()
    return redirect('dashboard')
