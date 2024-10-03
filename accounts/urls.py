from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

urlpatterns = [
    path('api/register/', register_user),
    path('api/login/', user_login),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/csrf-token/', csrf_token),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    path('google-login/', google_login, name='google_login'),
]
