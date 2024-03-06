from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from home.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/update/',UpdateImageView.as_view(),  name="update_image"),
    path('api/upload/',UploadImageView.as_view(),  name="upload_image"),
    path('api/delete/',DeleteImageView.as_view(), name="delete_image"), # For admin
    # path('update/<id>/',update_image, name="update_image"), # For admin
    path('api/superdashboard/',SuperDashboardView.as_view(), name="superdashboard"), # For admin
    path('api/dashboard/',DashboardView.as_view(), name="dashboard"), # For admin

    path('api/register/', UserRegistrationView.as_view(), name='api-register'),              # From Keywordlit Project
    path('api/verification/', UserEmailVerificationView.as_view(), name='api-verification'), # From Keywordlit Project
    path('api/resendotp/', ResendOTPView.as_view(), name='api-resendotp'),                   # From Keywordlit Project
    path('api/login/', UserLoginView.as_view(), name='api-login'),                           # From Keywordlit Project
    #path('api/refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),            # From Keywordlit Project
    path('api/profile/', UserProfileView.as_view(), name='api-profile'),                     # From Keywordlit Project
    path('api/forgot-password/', ForgotPasswordView.as_view(), name='api-forgotpassword'),    # From Keywordlit Project
    path('api/reset-password/', UserChangePasswordView.as_view(), name='api-resetpassword'),  # Change password is now RESETPASSWORD
    path('api/change-password/', UserModifyPasswordView.as_view(), name='api-changepassword'), # NEW CHANGE PASSOWRD FOR EXISTING USERS

    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# print(static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT))
