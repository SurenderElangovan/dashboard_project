from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .personal_utils import generate_verification_token, verify_token
from rest_framework.parsers import MultiPartParser, FormParser
import rest_framework.status as http_status
from django.contrib.auth import logout
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, RegisterSerializer, ResendVerificationSerializer, DeleteUserSerializer, ForgotPasswordSerializer, SetNewPasswordSerializer, UpdateUserSerializer, CustomPersonalUserSerializer
from .models import CustomPersonalUser
import uuid


class RegisterView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = generate_verification_token(user)

            verification_link = request.build_absolute_uri(
                reverse('verify', kwargs={'token': token})
            )

            send_mail(
                'Verify your account',
                f'Click to verify: {verification_link}',
                settings.EMAIL_HOST_USER,
                [user.email],
            )
            return Response({'message': 'Check your email for verification.'},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserView(APIView):
    def get(self, request, token):
        user_id = verify_token(token)
        if user_id:
            try:
                user = CustomPersonalUser.objects.get(id=user_id)
                if user.is_verified:
                    return Response({'message': 'Already verified.'}, status=status.HTTP_400_BAD_REQUEST)

                user.is_verified = True
                user.is_active = True
                user.save()
                return Response({'message': 'Account verified.'}, status=status.HTTP_200_OK)
            except CustomPersonalUser.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # `request.user` is the logged-in user due to IsAuthenticated permission
        user = request.user
        serializer = CustomPersonalUserSerializer(user)
        return Response(serializer.data, status=http_status.HTTP_200_OK)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        """user_data = {
            'username': user.username,
            'email': user.email,
            'is_verified': user.is_verified,
            'is_paid': user.is_paid,
            'profile_picture': user.profile_picture.url if user.profile_picture else None
        }

        # Return tokens along with user data
        return Response({
            'access': access_token,
            'refresh': str(refresh),
            'user': user_data
        }, status=http_status.HTTP_200_OK)"""

        return Response({
            'access': access_token,
            'refresh': str(refresh)
        }, status=http_status.HTTP_200_OK)


class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Extract the refresh token from the request body
            refresh_token = request.data.get('refresh')

            if not refresh_token:
                return Response({"detail": "Refresh token required."}, status=http_status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return Response({"detail": "Logout successful."}, status=http_status.HTTP_205_RESET_CONTENT)

        except Exception as e:
            return Response({"detail": "Invalid token or already blacklisted."}, status=http_status.HTTP_400_BAD_REQUEST)


class ResendVerificationView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email_data = {"email": request.user.email}
        serializer = ResendVerificationSerializer(data=email_data)
        serializer.is_valid(raise_exception=True)

        # Get the user object from the serializer
        user = serializer.user

        # Generate a new verification link
        verification_link = request.build_absolute_uri(
            reverse('verify-email',
                    kwargs={'token': str(user.email_verification_token)})
        )

        # Send the verification email
        send_mail(
            'Resend - Verify your account',
            f'Click to verify: {verification_link}',
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        return Response({"detail": "Verification email resent. Please check your inbox."}, status=status.HTTP_200_OK)


class DeleteUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Delete the user account
        request.user.delete()

        return Response({"detail": "User account deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = serializer.user

        # Generate a unique password reset token
        token = str(uuid.uuid4())
        user.password_reset_token = token
        user.save()

        # Send the password reset email
        reset_link = request.build_absolute_uri(
            reverse('set-new-password', kwargs={'token': token})
        )

        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_link}',
            settings.EMAIL_HOST_USER,
            [user.email],
        )

        return Response({"detail": "Password reset email sent. Please check your inbox."}, status=status.HTTP_200_OK)


class SetNewPasswordView(APIView):
    def post(self, request, token):
        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.user
        user.set_password(serializer.validated_data['password'])
        user.password_reset_token = ''  # Clear the token after resetting password
        user.save()

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


class UpdateUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        # partial=True allows updating specific fields
        serializer = UpdateUserSerializer(
            user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "User details updated successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
