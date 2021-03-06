from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('The username should only contain alphanumeric characters')
        return attrs

    """
            Create and return a new `User` instance, given the validated data.
    """
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=555, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)
        if not user:
            data = {
                'error': True,
                'message': 'Invalid credentials, try again'
            }
            raise AuthenticationFailed(data)
        if not user.is_active:
            data = {
                'error': True,
                'message': 'Account disabled, contact admin'
            }
            raise AuthenticationFailed(data)
        if not user.is_verified:
            data = {
                'error': True,
                'message': 'Email is not verified'
            }
            raise AuthenticationFailed(data)

        return {
                'email': user.email,
                'username': user.username,
                'tokens': {
                    'refresh': user.tokens()['refresh'],
                    'access': user.tokens()['access']
                }
            }
        return super().validate(attrs)
