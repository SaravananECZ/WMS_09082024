from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('create-account/<str:email>/', views.create_account, name='create_account'),
    path('login/', views.login, name='login'),
    path('password_reset/', views.password_reset, name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('warehouse-owner-details/', views.Warehouse_details_view, name='warehouse_owner_details'),
    path('manufacturer-details/', views.manufacturing_details_view, name='manufacturer_details'),
    # Other paths as needed
]
