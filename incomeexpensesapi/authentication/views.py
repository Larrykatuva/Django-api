from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import render
from django.utils.encoding import smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics, status, views
from .serializers import setNewPasswordSerializer, RegisterSerializer, EmailVerificationSerializer, LoginSerializer, RequestPasswordResetEmailSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util, ActivationCode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


# Create your views here.
class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absurl = 'http://' + current_site + relative_link + "?token=" + str(token)
        email_body = 'Hi ' + user.username + ' Use this link to verify your email \n' + absurl
        activation_code = ActivationCode(6).get_code()
        email_body1 = 'Hi ' + user.username + ' Use this code to verify your email \n CODE : ' + activation_code
        data = {'email_body': email_body,
                'to_email': user.email,
                'email_subject': 'Verify your email'}
        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                data = {
                    'error': False,
                    'message': 'Successfully activated'
                }
            return Response(data, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            data = {
                'error': True,
                'message': 'Activation expired'
            }
            return Response(data, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            data = {
                'error': True,
                'message': str(identifier)
            }
            return Response(data, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
            res_data = {
                'error': False,
                'message': 'We have sent you a link to reset your password'
            }
            return Response({'error': False,'message': 'We have sent you a link to reset your password'},
                            status=status.HTTP_200_OK)
        else:
            return Response({'error': True, 'message': 'The email provided does not exist'},
                            status=status.HTTP_200_OK)



class PasswordTokenCheckApi(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': True, 'message': 'Token is not valid please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)

            return Response({'error': False, 'message': 'Valid credentials', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_401_UNAUTHORIZED)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': True, 'message': 'Token is not valid please request a new one'},
                            status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = setNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'error': False, 'message': 'Password reset successfully'},
                        status=status.HTTP_200_OK)
