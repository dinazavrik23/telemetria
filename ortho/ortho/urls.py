from django.contrib import admin
from django.urls import path
from records import views as records_views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', records_views.login_view, name='login'),  # Страница входа по адресу /
    path('dashboard/', records_views.dashboard, name='dashboard'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('add_patient/', records_views.add_patient, name='add_patient'),
    path('add_visit/', records_views.add_visit, name='add_visit'),
    path('add_tooth/', records_views.add_tooth, name='add_tooth'),
    path('add_indicator/', records_views.add_indicator, name='add_indicator'),
    path('add_doctor/', records_views.add_doctor, name='add_doctor'),


]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)