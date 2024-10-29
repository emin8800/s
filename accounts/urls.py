from .views import *
from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

from accounts import views

urlpatterns = [
    path('api/register/', register_user),
    path('api/login/', user_login),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/csrf-token/', csrf_token),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'), 
    path('google-login/', google_login, name='google_login'),
    path('api/verify_code/', verify_code, name='verify_code'),
    path('resend-verification-code/', resend_verification_code, name='resend_verification_code'),

    path('api/user/', UserDetailView.as_view(), name='user_detail'),

    path('api/check-2fa/', views.check_2fa, name='check_2fa'),  # 2FA kontrolü için endpoint

    path('api/disable-2fa/', disable_2fa, name='disable-2fa'),
    path('api/enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
    path('api/verify-2fa/', Verify2FAView.as_view(), name='verify_2fa'),


    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),


]
