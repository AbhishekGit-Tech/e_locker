from . import views
from django.urls import path

urlpatterns = [
    path('', views.landing, name='landing'),
    path('login/', views.login_view, name='login'),
    path('login_simple/', views.login_simple_view, name='login_simple'),
    path('register/', views.register_view, name='register'),
    path('home/',views.home,name='home'),
    path('logout/', views.logout_view, name='logout'),

]