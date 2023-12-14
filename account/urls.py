from django.urls import path
from account.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, UserUpdateProfileView, \
      LogoutView, ValidateOTP, LoginWithOTP, ResetPasswordWithOTP

urlpatterns = [
      path('register/', UserRegistrationView.as_view(), name='register'),
      path('login/', UserLoginView.as_view(), name='login'),
      path('profile/', UserProfileView.as_view(), name='profile'),
      path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
      path('update/', UserUpdateProfileView.as_view(), name='update'),
      path('logout/', LogoutView.as_view(), name='logout'),
      path('login-with-otp/', LoginWithOTP.as_view(), name='login-with-otp'),
      path('validate-otp/', ValidateOTP.as_view(), name='validate-otp'),
      path('reset-password/', ResetPasswordWithOTP.as_view(), name='reset-password'),

]