from django.urls import path
from django.conf.urls.static import static 
from . import views
from django.conf import settings


urlpatterns = [
    path('dashboard/' , views.dashboard),
    path('about/' , views.about),
    path('login/' , views.login),
    path('signup/' , views.signup),
    path('ad/' , views.admin),
    path('Reports/', views.Reports),
    path('display/', views.display),
    path('new/', views.ipdisplay),
    path('up/' , views.UploadFiles )
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)