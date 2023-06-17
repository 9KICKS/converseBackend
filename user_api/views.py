from django.contrib.auth import get_user_model, login
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from .models import AppUser
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from .serializers import UserRegisterSerializer, UserLoginSerializer, UserSerializer
from rest_framework import permissions, status
from .validations import custom_validation, validate_email, validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.http import JsonResponse


class CustomPasswordChangeView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            userId = request.data.get('userId')
            token = request.data.get('token')
            user = AppUser.objects.get(pk=userId)
        except AppUser.DoesNotExist:
            return JsonResponse({"success": False, "message": "Invalid user."})

        token_generator = default_token_generator
        if not token_generator.check_token(user, token):
            return JsonResponse({"success": False, "message": "Invalid token."})

        password = request.data.get('password')
        user.set_password(password)
        user.save()
        return JsonResponse({"success": True, "message": "Password reset successfully."})


class CustomPasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        print(request.data.get("email"))
        try:
            user = AppUser.objects.get(email=email)
            print(user.email)
        except AppUser.DoesNotExist:
            return JsonResponse({"success": False, "message": "User with this email does not exist."})

        token_generator = default_token_generator
        token = token_generator.make_token(user)

        reset_url = f"http://localhost:3000/change/password/{user.pk}/{token}/"

        send_mail(
            subject="Reset your password",
            message=f"Click the following link to reset your password: {reset_url}",
            from_email="conversechatapplication@gmail.com",
            recipient_list=[user.email],
        )
        return JsonResponse({"success": True})


class UserRegister(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        try:
            clean_data = custom_validation(request.data)
            serializer = UserRegisterSerializer(data=clean_data)
            if serializer.is_valid(raise_exception=True):
                user = serializer.create(clean_data)
                if user:
                    subject = 'Converse registration'
                    message = "Hello, you have successfully registered to Converse. Let's converse 😉"
                    recipient = clean_data.get('email')
                    send_mail(subject, message, settings.EMAIL_HOST_USER, [recipient], fail_silently=False)

                    return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        data = request.data
        assert validate_email(data)
        assert validate_password(data)
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.check_user(data)
            login(request, user)
            return Response(serializer.data, status=status.HTTP_200_OK)


class UserView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response({'user': serializer.data}, status=status.HTTP_200_OK)
