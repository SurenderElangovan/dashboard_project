from django.urls import path
from .views import RegisterView, VerifyUserView, LoginView, LogoutView,ResendVerificationView,DeleteUserView,ForgotPasswordView,SetNewPasswordView,UpdateUserView, UserDetailView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify/<str:token>/', VerifyUserView.as_view(), name='verify'), #Mail url
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend-verification'),
    path('delete-user/', DeleteUserView.as_view(), name='delete-user'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('set-new-password/<uuid:token>/', SetNewPasswordView.as_view(), name='set-new-password'), #MAil url
    path('update-user/', UpdateUserView.as_view(), name='update-user'),
    path('user-details/', UserDetailView.as_view(), name='user-details'),
]
