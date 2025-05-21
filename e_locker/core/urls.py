from django.urls import path
from . import views

urlpatterns = [
    path('',              views.landing,          name='landing'),
    path('register/',     views.register_view,    name='register'),
    path('login_simple/', views.login_simple_view, name='login_simple'),
    path('login/',        views.login_otp_view,   name='login'),
    path('home/',         views.home,             name='home'),
    path('logout/',       views.logout_view,      name='logout'),
]
