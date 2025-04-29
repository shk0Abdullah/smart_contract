from django.urls import path
from . import views 

urlpatterns = [
    path('', views.audit, name='audit'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('index/', views.index, name='index'),
    path('chat/', views.chat, name = 'chat'),
    path('myaudits/',views.myaudit, name='myaudit'),
    path('myaudits/view/<str:filename>/', views.view_report, name='view_report'),
    path('myaudits/delete/<str:filename>/', views.delete_report, name='delete_report'),
    path('buy/',views.connector, name='buy'),
    path('settings/',views.settings, name='settings'),
    path("buy_callback/", views.buy_callback, name="buy_callback"),
    path('withdraw/',views.withdraw, name='withdraw'),
    path('user-activity/',views.user, name='user'),
    path('user/change-username',views.settings_username, name='change_username'),
    path('user/change-password',views.settings_password, name='change_password'),
    path('doc/',views.doc, name='doc'),
    path('contact/',views.contact, name='contact'),

    







]
