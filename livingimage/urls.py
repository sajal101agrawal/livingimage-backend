from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from home.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/update/',UpdateImageView.as_view(),  name="update_image"),
    path('api/update-user/',UpdateUserDeatilView.as_view(),  name="update_user"),
    path('api/upload/',UploadImageView.as_view(),  name="upload_image"),
    path('api/delete/',DeleteImageView.as_view(), name="delete_image"), # For admin
    # path('update/<id>/',update_image, name="update_image"), # For admin
    path('api/superdashboard/',SuperDashboardView.as_view(), name="superdashboard"), # For admin
    path('api/dashboard/',DashboardView.as_view(), name="dashboard"), # For admin

    path('api/credit-pricing/', CreditPricingAPIView.as_view(), name='credit_pricing'), #CREDIT
    path('api/record-payment/', RecordPaymentAPIView.as_view()), #PAYMENT
    path('api/get-payment-history/', GetPaymentHistoryAPIView.as_view()), #PAYMENT
    path('api/get-credit-history/', GetCreditHistoryAPIView.as_view()), #PAYMENT

    path('api/regenerate/', RegenerateImageView.as_view()), # REGENERATE IMAGE TEMPORARY as it will be automated

    path('api/register/', UserRegistrationView.as_view(), name='api-register'),              # From Keywordlit Project
    path('api/verification/', UserEmailVerificationView.as_view(), name='api-verification'), # From Keywordlit Project
    path('api/resendotp/', ResendOTPView.as_view(), name='api-resendotp'),                   # From Keywordlit Project
    path('api/login/', UserLoginView.as_view(), name='api-login'),                           # From Keywordlit Project
    #path('api/refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),            # From Keywordlit Project
    path('api/profile/', UserProfileView.as_view(), name='api-profile'),                     # From Keywordlit Project
    path('api/forgot-password/', ForgotPasswordView.as_view(), name='api-forgotpassword'),    # From Keywordlit Project
    path('api/reset-password/', UserChangePasswordView.as_view(), name='api-resetpassword'),  # Change password is now RESETPASSWORD
    path('api/change-password/', UserModifyPasswordView.as_view(), name='api-changepassword'), # NEW CHANGE PASSOWRD FOR EXISTING USERS


    path('api/get-public-original-image/', GetPublicOriginalImage.as_view(), name='GetPublicOriginalImage'), # DONE
    path('api/get-public-regen-image/', GetPublicRegenrativeImage.as_view(), name='GetPublicRegenrativeImage'), # DONE
    path('api/get-all-regen-image/', GetAllRegenrativeImage.as_view(), name='GetAllRegenrativeImage'), # DONE
    path('api/get-all-original-image/', GetAllOriginalImage.as_view(), name='GetAllOriginalImage'), # DONE
    path('api/get-one-regen-image/', GetOneRegenrativeImage.as_view(), name='GetOneRegenrativeImage'),
    path('api/get-one-original-image/', GetOneOriginalImage.as_view(), name='GetOneOriginalImage'),

    path('api/admin/update-credit-price/', UpdateCreditPricingAPIView.as_view(), name='update_credit_price'),# Admin CREDIT
    path('api/admin/get-all-payment/', GetAllPayments.as_view(), name='GetAllPayments'),  # Admin  assertion Error
    path('api/admin/get-all-user/', GetAllUsers.as_view(), name='GetAllUsers'),  # Admin
    path('api/admin/delete-user/', DeleteUser.as_view(), name='DeleteUser'),  # Admin
    path('api/admin/view-user/', ViewUser.as_view(), name='ViewUser'),  # Admin
    path('api/admin/update-user-admin/', AdminUpdateUser.as_view(), name='UpdateUser'),  # Admin # Only Name can be updated
    path('api/admin/get-all-regen-admin/', AdminGetAllRegenrativeImage.as_view(), name='AdminGetAllRegenrativeImage'),  # Admin
    path('api/admin/get-all-original-admin/', AdminGetAllOriginalImage.as_view(), name='AdminGetAllOriginalImage'),  # Admin
    path('api/admin/get-one-regen-admin/', AdminGetOneRegenrativeImage.as_view(), name='AdminGetOneRegenrativeImage'),  # Admin
    path('api/admin/get-one-original-admin/', AdminGetOneOriginalImage.as_view(), name='AdminGetOneOriginalImage'),  # Admin
    path('api/admin/analytics/', AdminAnalytics.as_view(), name='AdminAnalytics'),  # Admin

    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# print(static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT))
