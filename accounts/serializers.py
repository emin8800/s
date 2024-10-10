from .models import CustomUser
from rest_framework import serializers
from django.contrib.auth.forms import PasswordResetForm

############################################################UserSerializer#########################################################################################################

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'first_name', 'last_name', 'telephone', 'verification_code', 'is_verified']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'], 
            last_name=validated_data['last_name'],   
            telephone=validated_data['telephone'],    
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
#########################################################PasswordResetSerializer#################################################################################
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # E-posta adresi kayıtlı değilse hata döner
        if not PasswordResetForm({'email': value}).is_valid():
            raise serializers.ValidationError("Bu e-posta kayıtlı değil.")
        return value

