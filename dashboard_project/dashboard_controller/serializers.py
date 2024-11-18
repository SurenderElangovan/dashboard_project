from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError
import re
from PIL import Image as PILImage
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from django.core.exceptions import ObjectDoesNotExist


User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    profile_picture = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'profile_picture']

    def validate_username(self, value):
        # Check for spaces or special characters
        if ' ' in value:
            raise ValidationError("Username cannot contain spaces.")
        if not re.match(r'^[\w.@+-]+$', value):  # Alphanumeric + allowed characters
            raise ValidationError("Username may only contain alphanumeric characters and @/./+/-/_ symbols.")
        return value

    def validate_email(self, value):
        # Check for existing email
        if User.objects.filter(email=value).exists():
            raise ValidationError("A user with this email already exists.")
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_profile_picture(self, value):
        if value:
            if not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
                raise ValidationError("Profile picture must be a PNG or JPG image.")
            if value.size > 5 * 1024 * 1024:  # 5 MB limit
                raise ValidationError("Profile picture must not exceed 5MB in size.")
            try:
                img = PILImage.open(value)
                img.verify()  # Verify the image content
            except (IOError, SyntaxError) as e:
                raise serializers.ValidationError("Upload a valid image !. The file you uploaded was either not an image or a corrupted image.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            profile_picture=validated_data.get('profile_picture'),
        )
        user.is_active = False
        user.save()
        return user
    
class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username_or_email = data.get('username_or_email')
        password = data.get('password')

        # Attempt to authenticate using username or email
        user = self._authenticate_user(username_or_email, password)

        if not user:
            raise AuthenticationFailed("Invalid username/email or password.")
        
        if not user.is_active:
            raise AuthenticationFailed("This account is not active.")

        return {'user': user}

    def _authenticate_user(self, username_or_email, password):
        """Helper function to authenticate by username or email."""
        # Check if the input is an email or a username
        user = None
        if User.objects.filter(email=username_or_email).exists():
            user = User.objects.get(email=username_or_email)
        elif User.objects.filter(username=username_or_email).exists():
            user = User.objects.get(username=username_or_email)

        # Use Django's authenticate method to validate the password
        if user:
            authenticated_user = authenticate(username=user.username, password=password)
            return authenticated_user  # Returns None if the password is incorrect
        return None
    
class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Check if the user with this email exists
        try:
            user = User.objects.get(email=value)
            if user.is_verified:
                raise serializers.ValidationError("Email is already verified.")
        except ObjectDoesNotExist:
            raise serializers.ValidationError("No user found with this email.")

        # Store the user object for later use
        self.user = user
        return value
    
class DeleteUserSerializer(serializers.Serializer):
    confirm = serializers.BooleanField()

    def validate_confirm(self, value):
        if not value:
            raise serializers.ValidationError("You must confirm the deletion by setting this field to True.")
        return value
    
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Check if the user with this email exists
        try:
            user = User.objects.get(email=value)
        except ObjectDoesNotExist:
            raise serializers.ValidationError("No user found with this email.")

        # Store the user object for later use
        self.user = user
        return value
    
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    token = serializers.UUIDField(format='hex')

    def validate_token(self, value):
        # Check if the token is valid and belongs to an existing user
        try:
            user = User.objects.get(password_reset_token=value)
            if not user:
                raise serializers.ValidationError("Invalid token.")
            self.user = user
        except ObjectDoesNotExist:
            raise serializers.ValidationError("Invalid token.")
        return value
    
class UpdateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email', 'profile_picture', 'password']

    def validate_email(self, value):
        # Check if the email is already in use by another user
        if User.objects.exclude(pk=self.instance.pk).filter(email=value).exists():
            raise ValidationError("This email is already in use.")
        return value

    def update(self, instance, validated_data):
        # If password is provided, set the new password
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        # Update other fields
        if 'email' in validated_data:
            instance.email = validated_data.get('email', instance.email)
        if 'profile_picture' in validated_data:
            instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
        #instance.save()
        return super().update(instance, validated_data)
    
class CustomPersonalUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Specify the fields you want to include in the response
        fields = ['id', 'username', 'email', 'profile_picture', 'is_verified', 'is_paid']