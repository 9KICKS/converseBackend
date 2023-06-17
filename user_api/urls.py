from django.urls import path
from . import views

urlpatterns = [
    path('register', views.UserRegister.as_view(), name='register'),
    path('login', views.UserLogin.as_view(), name='login'),
    path('user', views.UserView.as_view(), name='user'),
    path('reset', views.CustomPasswordResetView.as_view(), name='reset'),
    path('change/password', views.CustomPasswordChangeView.as_view(), name='change password')
]
