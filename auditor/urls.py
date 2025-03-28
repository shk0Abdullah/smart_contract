from django.urls import path
from . import views

urlpatterns = [
    path('', views.audit, name='audit'),
    path('index/', views.index, name='index'),
    path('chat/', views.chat, name = 'chat'),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("register", views.register, name="register"),
   


]
