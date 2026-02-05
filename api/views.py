import os
from rest_framework import viewsets, permissions, status, generics
from rest_framework.response import Response
from rest_framework.decorators import action
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.core.mail import send_mail
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth import authenticate
from users.models import User, Review
from agents.models import Agent, Tool
from .serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer
from .serializers import (
    UserSerializer, ReviewSerializer, AgentSerializer, 
    ToolSerializer
)
from .permissions import IsAdmin
import threading
import requests
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView

class RegisterView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    def create(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                'message': 'User registered successfully',
                'token': token.key,
                'role': getattr(user, 'role', None)
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(viewsets.ViewSet):
    permission_classes = [permissions.AllowAny]
    @action(detail=False, methods=['post'])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response(
                {"error": "Email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = authenticate(request, email=email, password=password)
        if not user:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            "token": token.key,
            "id": user.id,
            "email": user.email,
            "role": user.role
        })


class LogoutView(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, Token.DoesNotExist):
            pass
        return Response({"message": "User logged out successfully"}, status=status.HTTP_200_OK)


class ReviewViewSet(viewsets.ModelViewSet):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        user = self.request.user
        if user.role.lower() == "admin":
            return Review.objects.all()
        else:
            return Review.objects.filter(user=user)
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    def destroy(self, request, *args, **kwargs):
        user = request.user
        if user.role.lower() != "admin":
            return Response({"error": "You do not have permission to delete reviews"}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        user = self.request.user
        role = getattr(user, 'role', '').lower()
        if role == 'admin':
            return User.objects.all()
        elif role == 'user':
            return User.objects.filter(id=user.id)
        else:
            return User.objects.none()
    def perform_update(self, serializer):
        user = self.request.user
        role = getattr(user, 'role', '').lower()
        if role == 'admin' or user.id == serializer.instance.id:
            serializer.save()
        else:
            raise PermissionDenied({"error": "You do not have permission to update this user."})
    def perform_destroy(self, instance):
        user = self.request.user
        role = getattr(user, 'role', '').lower()
        if role == 'admin' or user.id == instance.id:
            instance.delete()
        else:
            raise PermissionDenied({"error": "You do not have permission to delete this user."})
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


class AgentViewSet(viewsets.ModelViewSet):
    queryset = Agent.objects.all()
    serializer_class = AgentSerializer
    lookup_field = 'agent_id'
    permission_classes = [permissions.IsAuthenticated, IsAdmin]


class ToolViewSet(viewsets.ModelViewSet):
    queryset = Tool.objects.all().order_by('tool_name')
    serializer_class = ToolSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_400_BAD_REQUEST)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"{settings.FRONTEND_URL}/reset/{uid}/{token}/"
            send_mail(
                "Password Reset Requested",
                f"Click the link to reset your password: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False
            )
            return Response({'message': 'Reset link sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)