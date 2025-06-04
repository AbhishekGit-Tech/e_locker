from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('',              views.landing,          name='landing'),
    path('register/',     views.register_view,    name='register'),
    path('login_simple/', views.login_simple_view, name='login_simple'),
    path('login/',        views.login_otp_view,   name='login'),
    path('home/',         views.home,             name='home'),
    path('logout/',       views.logout_view,      name='logout'),
    path('upload/', views.upload_file, name='upload_file'),
    path('open/<int:file_id>/',    views.open_anyway,   name='open_anyway'),
    path('decrypt/<int:file_id>/', views.decrypt_view, name='decrypt'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('profile/',       views.profile_view,    name='profile'),
    path('profile/otp/',   views.profile_verify,  name='profile_verify'),
    path('profile/remove_picture/', views.remove_picture, name='remove_picture'),
    path('account/delete/',     views.delete_account,       name='delete_account'),
    path('account/delete/confirm/', views.confirm_delete_account, name='confirm_delete_account'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
