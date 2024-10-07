from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView  # Burada APIView'ı import edin
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.contrib.auth import authenticate
from .serializers import UserSerializer
from .models import CustomUser

@api_view(['POST'])
def register_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)

    if user:
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'csrfToken': get_token(request) 
        }, status=status.HTTP_200_OK)

    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Token'ı kara listeye ekler

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


def csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})




from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import PasswordResetSerializer

class PasswordResetAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            # Şifre sıfırlama işlemini başlat
            form = PasswordResetForm(serializer.validated_data)
            if form.is_valid():
                form.save(
                    request=request,
                    use_https=False,  # https kullanıyorsan True yapabilirsin
                    email_template_name='registration/password_reset_email.html',
                    from_email=settings.DEFAULT_FROM_EMAIL
                )
                return Response({'message': 'Şifre sıfırlama e-postası gönderildi.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






# import requests
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status

# from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

# @api_view(['POST'])
# def google_login(request):
#     token = request.data.get('token')
    
#     if not token:
#         return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

#     # Google token doğrulaması
#     google_response = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={token}')

#     if google_response.status_code != 200:
#         return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)

#     google_data = google_response.json()
#     email = google_data.get('email')

#     if not email:
#         return Response({'error': 'Email not provided'}, status=status.HTTP_400_BAD_REQUEST)

#     # Kullanıcıyı veritabanında bul veya oluştur
#     user, created = CustomUser.objects.get_or_create(email=email)

#     # JWT Token oluşturma
#     access = AccessToken.for_user(user)
#     refresh = RefreshToken.for_user(user)

#     return Response({
#         'access': str(access),
#         'refresh': str(refresh)
#     }, status=status.HTTP_200_OK)












####2ci
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.utils.text import slugify  # Kullanıcı adı için
from .models import CustomUser

@api_view(['POST'])
def google_login(request):
    try:
        token = request.data.get('token')

        if not token:
            return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Google token doğrulaması
        google_response = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={token}')

        if google_response.status_code != 200:
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)

        google_data = google_response.json()
        print("Google Data:", google_data)  # Hata ayıklama için

        email = google_data.get('email')
        if not email:
            return Response({'error': 'Email not provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Kullanıcıyı veritabanında bul veya oluştur
        user, created = CustomUser.objects.get_or_create(email=email)

        if created:
            # Yeni kullanıcıysa, username ve diğer bilgileri ayarlayın
            first_name = google_data.get('given_name', '')
            last_name = google_data.get('family_name', '')

            username = slugify(f'{first_name} {last_name}'[:30])  # max 30 karakter
            user.username = username if username else email  # Username boşsa email kullan
            user.first_name = first_name
            user.last_name = last_name

            # Kullanıcıyı kaydet
            try:
                user.save()
            except Exception as e:
                print("User creation error:", str(e))  # Hata ayıklama için
                return Response({'error': 'User creation failed', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # JWT Token oluşturma
        access = AccessToken.for_user(user)
        refresh = RefreshToken.for_user(user)

        return Response({
            'access': str(access),
            'refresh': str(refresh),
            'message': 'User registered' if created else 'User logged in'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        print("Internal server error:", str(e))  # Hata ayıklama için
        return Response({'error': 'Internal server error', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

