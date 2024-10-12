import random
import requests
from drf import settings
from .models import CustomUser
from datetime import timedelta
from rest_framework import status
from django.http import JsonResponse
from django.utils.text import slugify
from django.core.mail import send_mail
from .serializers import UserSerializer
from rest_framework.views import APIView 
from rest_framework.response import Response
from django.middleware.csrf import get_token
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view
from .serializers import PasswordResetSerializer
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.forms import PasswordResetForm
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken


#########################################Register Api#############################################################
@api_view(['POST'])
def register_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save(is_verified=False)  
    
        verification_code = random.randint(100000, 999999)

        send_mail(
            'Doğrulama Kodu',
            f'Sizin doğrulama kodunuz: {verification_code}',
            settings.DEFAULT_FROM_EMAIL,  
            [user.email],
            fail_silently=False,
        )

        user.verification_code = verification_code
        user.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#########################################Login Api#############################################################

@api_view(['POST'])
def user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    recaptcha_token = request.data.get('recaptchaToken')
    remember_me = request.data.get('rememberMe', False) 

    if not recaptcha_token:
        return Response({'error': 'reCAPTCHA doğrulaması gerekli'}, status=status.HTTP_400_BAD_REQUEST)

    recaptcha_url = "https://www.google.com/recaptcha/api/siteverify"
    recaptcha_data = {
        'secret': settings.RECAPTCHA_SECRET_KEY,
        'response': recaptcha_token
    }

    recaptcha_response = requests.post(recaptcha_url, data=recaptcha_data)
    recaptcha_result = recaptcha_response.json()

    if not recaptcha_result.get('success'):
        return Response({'error': 'reCAPTCHA doğrulaması başarısız'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user:
        if not user.is_verified:
            return Response({'error': 'Kullanıcı doğrulanmamış. Lütfen doğrulama kodunu girin.'}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)

        if remember_me:
            access_lifetime = timedelta(days=1) 
        else:
            access_lifetime = timedelta(minutes=5)  

        access = AccessToken.for_user(user)
        access.set_exp(lifetime=access_lifetime)

        return Response({
            'refresh': str(refresh),
            'access': str(access),
            'csrfToken': get_token(request)  
        }, status=status.HTTP_200_OK)

    return Response({'error': 'Geçersiz kimlik bilgileri'}, status=status.HTTP_401_UNAUTHORIZED)

#########################################Google Login Api#############################################################

@api_view(['POST'])
def google_login(request):
    try:
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        if not email:
            return Response({'error': 'Email not provided'}, status=status.HTTP_400_BAD_REQUEST)

        user, created = CustomUser.objects.get_or_create(email=email)

        if created:
            user.first_name = first_name
            user.last_name = last_name
            user.username = slugify(f'{first_name} {last_name}'[:30]) 
            user.is_verified = True  
            user.save()

        access = AccessToken.for_user(user)
        refresh = RefreshToken.for_user(user)

        return Response({
            'access': str(access),
            'refresh': str(refresh),
            'username': user.username, 
            'message': 'User registered' if created else 'User logged in'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': 'Internal server error', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#########################################Logout Api#############################################################

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

#########################################Verify Code Api#############################################################

@api_view(['POST'])
def verify_code(request):
    email = request.data.get('email')
    code = request.data.get('code')

    try:
        user = CustomUser.objects.get(email=email)
        if user.verification_code == int(code):
            user.is_verified = True
            user.verification_code = None  
            user.save()
            return Response({"message": "Doğrulama başarılı!"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Geçersiz kod!"}, status=status.HTTP_400_BAD_REQUEST)
    except CustomUser.DoesNotExist:
        return Response({"error": "Kullanıcı bulunamadı!"}, status=status.HTTP_404_NOT_FOUND)

######################################### Resend Verification Code Api#############################################################

@api_view(['POST'])
def resend_verification_code(request):
    email = request.data.get('email')
    
    try:
        user = CustomUser.objects.get(email=email)
        if user.is_verified:
            return Response({"error": "Kullanıcı zaten doğrulanmış."}, status=status.HTTP_400_BAD_REQUEST)

        verification_code = random.randint(100000, 999999)

        send_mail(
            'Yeni Doğrulama Kodu',
            f'Sizin yeni doğrulama kodunuz: {verification_code}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        user.verification_code = verification_code
        user.save()

        return Response({"message": "Yeni doğrulama kodu gönderildi."}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        return Response({"error": "Kullanıcı bulunamadı!"}, status=status.HTTP_404_NOT_FOUND)

######################################### Password Reset Api#############################################################

# class PasswordResetAPIView(APIView):
#     def post(self, request):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             form = PasswordResetForm(serializer.validated_data)
#             if form.is_valid():
#                 form.save(
#                     request=request,
#                     use_https=False,  
#                     email_template_name='registration/password_reset_email.html',
#                     from_email=settings.DEFAULT_FROM_EMAIL
#                 )
#                 return Response({'message': 'Şifre sıfırlama e-postası gönderildi.'}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

######################################### CSRF-TOKEN Api#############################################################

def csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})


########################################################################################################################

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .models import CustomUser
from django.utils.http import urlsafe_base64_decode

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get("email")
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "Kullanıcı bulunamadı."}, status=status.HTTP_404_NOT_FOUND)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # E-posta içeriğini oluştur
        subject = "Şifre Sıfırlama Talebi"
        message = render_to_string('password_reset_email.html', {
            'uid': uid,
            'token': token,
            'user': user,
        })
        send_mail(subject, message, 'your_email@example.com', [user.email])

        return Response({"success": "Şifre sıfırlama bağlantısı e-posta ile gönderildi."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        new_password = request.data.get("new_password")
        re_new_password = request.data.get("re_new_password")

        # Şifrelerin eşleşip eşleşmediğini kontrol et
        if new_password != re_new_password:
            return Response({"error": "Şifreler eşleşmiyor."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({"success": "Şifreniz başarıyla sıfırlandı."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Geçersiz bağlantı."}, status=status.HTTP_400_BAD_REQUEST)
