from django.shortcuts import render, redirect
from .forms import ImageForm#, ProfilePicForm
from .models import *
from rest_framework.views import APIView
from rest_framework.response import Response
from .email import send_otp_via_email
import random
import json
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_random_string, get_user_id_from_token
from .serializers import  UserChangePasswordSerializer, UserLoginSerializer, UserProfileSerializer, UserRegistrationSerializer, UserChangePasswordSerializer, UserModifyPasswordSerializer
from rest_framework.permissions import BasePermission, IsAuthenticated, AllowAny
from .renderers import UserRenderer
from django.views import View
from django.http import JsonResponse, HttpResponse
import os
from django.conf import settings
from PIL import Image as PILImage
from io import BytesIO
import boto3
from django.core.files.storage import default_storage
from botocore.exceptions import ClientError
import pytz
import io
from openai import OpenAI
import requests
from rest_framework.pagination import PageNumberPagination
# Create your views here.

#----------------------Code copied from Keywordlit Project----------------------------------------------------------------

def IsSuperUser(user_id):
    user = CustomUser.objects.filter(id=user_id)
    if not user : return False, False
    user = user.first()
    return user , user.is_superuser
    
def get_or_createToken(request):
    """ 
    Create a user access token for already logged in user
    """
    if request.user.is_authenticated  :
        user = CustomUser.objects.get(email = request.user.email)
        token = get_tokens_for_user(user)
        request.session['access_token'] = token['access']
        return request.session['access_token']
    else:
        return False

def get_tokens_for_user(user):
    """ 
    Get a token access for already logged in user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        # 'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
      


class UserRegistrationView(APIView):
    """ 
    An API view for user registration and return error if there is any error or insufficient data provided
    """
    renderer_classes = [UserRenderer]
    
    def post(self, request, format=None):
        if not 'username' in request.data:
            while True:
                generated_random_username = generate_random_string(15)
                if CustomUser.objects.filter(username=generated_random_username).count() == 0:
                    request.data['username'] = generated_random_username
                    break

        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.data.get('email'):
            return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)

        is_superuser = request.data.get('isAdmin', False)
        if is_superuser:
            user = CustomUser.objects.create_superuser(**serializer.validated_data)
            user.is_user_verified = True  # ALL superuser are verified
            user.save()
            return Response({"email": 'Email is verified', 'Message': 'Admin user Created'},
                        status=status.HTTP_201_CREATED)
        
        else:
            user = serializer.save()

            verification_code = random.randint(100000, 999999)
            user.verification_code = verification_code
            user.save()

            try:
                send_otp_via_email(user.email)  # Use your send_otp_via_email function
            except ValidationError as e:
                return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"email": f'{user.email}', 'Message': ' Email verification code has been sent, Verify your account'},
                            status=status.HTTP_201_CREATED)






#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
    
class UserEmailVerificationView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        # Check if required fields are provided
        if not email or not verification_code:
            return Response({'Message': 'Please provide Email and Verification code'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)

            if user.is_user_verified == True:
                # If user is already verified, return a message indicating so
                return Response({'Message': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
             # Check if verification code is a valid number
            if not verification_code.isdigit():
                return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

            if str(user.verification_code) == verification_code:
                user.is_user_verified = True
                token = get_tokens_for_user(user)
                verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
                user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
                user.save()
                if user.membership:
                    Mem=Membership.objects.filter(name=user.membership.name).first()
                    memebership_id=Mem.id
                    return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":memebership_id, "membership":user.membership.name, "membership_expiry_date":str(user.membership_expiry), "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                else:
                    return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                # return Response({'token':token,'Message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'Entered Verification code is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            # If email is not in records, prompt user to register first
            return Response({'Message': 'Email not in records. Please register first.'}, status=status.HTTP_400_BAD_REQUEST)

#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
 
#---------------------------------------------------------Resend OTP API by ADIL----------------------------------------------------------------

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'Message': 'Please provide an email address.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
            verification_code = random.randint(100000, 999999)
            user.verification_code = verification_code
            user.save()
            # Call the function to send OTP via email
            send_otp_via_email(email)
            return Response({'Message': 'New verification code sent successfully.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'Message': 'Email not found in records. Register First'}, status=status.HTTP_404_NOT_FOUND)


#---------------------------------------------------------Resend OTP APY by ADIL---------------------------------------------------------------




class UserLoginView(APIView):
    """ 
    send an username and exist user's password to get user's accesstoken.
    """
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        #user = CustomUser.objects.get(email = email)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # If the email is not found in records, return a 404 NotFound response
            return Response({'Message': 'Email not in record. Register First!'}, status=status.HTTP_404_NOT_FOUND)

        if user.check_password(password)  :
            if user.is_user_verified:
                token = get_tokens_for_user(user)
                user, is_superuser = IsSuperUser(user.id)
                if user.membership:
                    Mem=Membership.objects.filter(name=user.membership.name).first()
                    memebership_id=Mem.id
                    return Response({'token':token,'verified' : user.is_user_verified, 'admin' : is_superuser, 'Message':'Login Success', "membership_id":memebership_id, "membership":user.membership.name, "membership_expiry_date":str(user.membership_expiry), "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                else:
                    return Response({'token':token,'verified' : user.is_user_verified, 'admin' : is_superuser, 'Message':'Login Success', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)

            else:
#--------------------------If user is not verified then OTP is sent to user-----------------------------------------------------------
                verification_code = random.randint(100000, 999999)
                user.verification_code = verification_code
                user.save()
                try:
                    send_otp_via_email(user.email)  # Use your send_otp_via_email function
                except ValidationError as e:
                    return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#--------------------------If user is not verified then OTP is sent to user-----------------------------------------------------------
                return Response({'verified' : user.is_user_verified, 'Message':'Verify your account First!', 'Email': user.email}, status=status.HTTP_200_OK)
        else:
            return Response({'Message':'Email or Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)

class RefreshTokenView(APIView):
    """
    Send a refresh token to get a new access token.
    """
    def post(self, request, format=None):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'Message': 'No refresh token provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh_token = RefreshToken(refresh_token)
            access_token = refresh_token.access_token
        except Exception as e:
            return Response({'Message': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'access_token': str(access_token)}, status=status.HTTP_200_OK)
    
class UserProfileView(APIView):
    """ 
    Get a user profile data with email and password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        Image_history = []
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        #print("the user is",user.email)
        image_count=0
        for history in Image.objects.filter(user=user) :
#-------------------------Code to fetch the error in the section---------------------------------------------------
            # try:
            #     # Attempt to load the JSON data, replacing single quotes with double quotes
            #     result_json = json.loads(history.result.replace("'", '"'))
            # except json.JSONDecodeError as e:
            #     # Handle JSON decoding errors, for example by skipping the problematic entry
            #     print(f"Error decoding JSON for history ID {history.id}: {e}")
            #     print(f"Error decoding JSON for history platform {history.image_data}: {e}")
            #     print(f"Error decoding JSON for history hashtag {history.prompt}: {e}")
            #     print(f"Error decoding JSON for history date {history.created}: {e}")
            #     continue
#-------------------------Code to fetch the error in the section---------------------------------------------------
            
            tmp = {
                'user' : history.user.email,
                'image_id' : history.id,
                'image_data' : str(history.photo),
                'public' : history.public,
                'prompt' : history.prompt,
                'frequency_type' : history.frequency_type,#created.strftime("%d/%m/%Y"),
                'frequency' : history.frequency,#json.loads(history.result.replace("'", "\"")),
                'created': history.created.strftime("%d/%m/%Y %H:%M:%S"),
                'updated': history.updated.strftime("%d/%m/%Y %H:%M:%S"),
            }
            Image_history.append(tmp)
            image_count=len(Image_history)
        
        diposit_history = []
        for MoneyHistory in DepositeMoney.objects.filter(user=user):
            tmp = {
                'deposit_id' : MoneyHistory.id,
                'date' : MoneyHistory.created.strftime("%d/%m/%Y %H:%M:%S"),
                'amount' : MoneyHistory.Amount,
                'transection_id' : MoneyHistory.TransactionId,
                'method' : MoneyHistory.method,
                'status' : MoneyHistory.status
            }
            diposit_history.append(tmp)
        
        if user.profile_photo:
            photo = str(user.profile_photo)
        else:
            photo = None
                
        jsonn_response = {
            'personal_data' : serializer.data,
            'profile_pic': photo,
            'Total_Image_count' : image_count,
            #'Image_data' : Image_history,
            #'deposit_history' : diposit_history
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response
    
# ------------------------------------- USER PROFILE PICTURE --------------------------------------------------------------------
class GetUserProfilePic(APIView):
    """ 
    Get a user profile data with email and password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try: 
            if user.profile_photo:
                photo = user.profile_photo
                return Response({'Message': 'Profile Photo Fetched successfully.', 'Profile_Picture': str(photo) }, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'User has no profile picture.', 'Profile_Picture': None}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f'Profile Photo Fetching Unsuccessful, {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
 
class SetUserProfilePic(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Retrieve the authenticated user
            user = request.user
             
            # Retrieve the uploaded file from request.FILES
            profile_photo = request.FILES.get('photo')
            
            if not profile_photo:
                return Response({'Message': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if the size of the uploaded image is within the limit
            max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
            if profile_photo.size > max_size:
                return Response({'Message': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=status.HTTP_400_BAD_REQUEST)

            # Initialize S3 client
            s3_client = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_S3_REGION_NAME
            )

            # Check if the user already has a profile picture stored in S3
            if user.profile_photo and str(user.profile_photo).startswith('https://'):
                # Extract the S3 bucket name and key from the existing profile photo URL
                bucket_name, key = self.extract_bucket_and_key(str(user.profile_photo))

                # Upload the file to the existing S3 bucket
                # s3_client.upload_fileobj(profile_photo, bucket_name, key)
                
                # Upload the file to the existing S3 bucket with inline Content-Disposition
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=profile_photo,
                    ContentType=profile_photo.content_type,
                    ContentDisposition='inline'  # Set Content-Disposition to inline
                )


                # Construct the S3 URL for the uploaded photo
                s3_url = f"https://{bucket_name}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{key}"

                # Update the user's profile_photo field with the new S3 URL
                user.profile_photo = s3_url
                user.save()

                return Response({'Message': 'Profile Pic Update Successful.', 'S3_URL': s3_url}, status=status.HTTP_200_OK)
            else:
                # Upload the file to a new S3 bucket (Assuming you want to use a different bucket for new uploads)
                bucket_name = settings.AWS_STORAGE_BUCKET_NAME3
                key = f"profile_pic/{user.id}/{profile_photo.name}"

                # Upload the file to the new S3 bucket
                # s3_client.upload_fileobj(profile_photo, bucket_name, key)

                # Upload the file to the new S3 bucket with inline Content-Disposition
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=profile_photo,
                    ContentType=profile_photo.content_type,
                    ContentDisposition='inline'  # Set Content-Disposition to inline
                )

                # Construct the S3 URL for the uploaded photo
                s3_url = f"https://{bucket_name}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{key}"

                # Update the user's profile_photo field with the new S3 URL
                user.profile_photo = s3_url
                user.save()

                return Response({'Message': 'Profile Pic Update Successful.', 'S3_URL': s3_url}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'Message': f'Profile Pic Update Failed: {e}'}, status=status.HTTP_400_BAD_REQUEST)

    def extract_bucket_and_key(self, s3_url):
        """Extracts S3 bucket name and key from the S3 URL."""
        # Example S3 URL: "https://bucket-name.s3.region.amazonaws.com/key"
        parts = s3_url.split('/')
        bucket_name = parts[2].split('.')[0]
        key = '/'.join(parts[3:])
        return bucket_name, key



# ------------------------------------- USER PROFILE PICTURE --------------------------------------------------------------------

class UserModifyPasswordView(APIView):
    """ 
    Change existing user password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserModifyPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')

        # Check if the old password matches the user's current password
        if not user.check_password(old_password):
            return Response({'Message': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the old and new passwords are the same
        if old_password == new_password:
            return Response({'Message': 'New password must be different from the old password.'}, status=status.HTTP_400_BAD_REQUEST)

        # Change the user's password
        user.set_password(new_password)
        user.save()

        return Response({'Message': 'Password changed successfully.'}, status=status.HTTP_200_OK)



#---------------------------------------------Change Password by Adil------------------------------------------------------------

class UserChangePasswordView(APIView):
    """ 
    Reset user password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]  # Allow any user to access this endpoint

    def post(self, request, format=None):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        new_password = request.data.get('new_password')

        # Check if required fields are provided
        if not email or not verification_code or not new_password:
            return Response({'Message': 'Please provide the Email, Verification code and New Password'}, status=status.HTTP_400_BAD_REQUEST)

         # Check if verification code is a valid number
        if not verification_code.isdigit():
            return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email, verification_code=verification_code)
            verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times.
            user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times.
            user.save()# Extra Code added to change the code after Process because same code will be used multiple times.
        except CustomUser.DoesNotExist:
            return Response({'Message': 'Invalid email or verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserChangePasswordSerializer(instance=user, data={'password': new_password, 'password2': new_password})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'Message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            # Handle validation errors
            return Response({'Message': e.detail}, status=status.HTTP_400_BAD_REQUEST)


#---------------------------------------------Change Password by Adil------------------------------------------------------------







#---------------------------------Forgot Password by Adil--------------------------------------------------------------------

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'Message': 'Please provide the Email'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Check if user exists in records
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # If user is not in records, prompt user to register first
            return Response({'Message': 'User not in records. Register first.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a verification code
        verification_code = random.randint(100000, 999999)
        user.verification_code = verification_code
        user.save()

        # Send verification code via email
        send_otp_via_email(email)

        return Response({'Message': 'Password Reset code sent successfully. Use it to reset your password.'}, status=status.HTTP_200_OK)

#------------------------------------Forgot Password by Adil---------------------------------------------------------------
    
# ------------------------------------Regenrative Time Calculate -----------------------------------------------------------------
def calculate_regeneration_time(frequency,frequency_type):
        frequency=int(frequency)
        # Calculate the next regenerative_at datetime based on frequency and frequency_type
        now_utc = datetime.now(pytz.utc)
        if frequency_type == 'day':
            regenerative_at = now_utc + timedelta(days=frequency)
        elif frequency_type == 'week':
            regenerative_at = now_utc + timedelta(weeks=frequency)
        elif frequency_type == 'month':
            regenerative_at = now_utc + timedelta(days=30 * frequency)
        elif frequency_type == 'year':
            regenerative_at = now_utc + timedelta(days=365 * frequency)
        elif frequency_type == 'hour':
            regenerative_at = now_utc + timedelta(hours= frequency)
        elif frequency_type == 'minute':
            regenerative_at = now_utc + timedelta(minutes= frequency)
        elif frequency_type == 'second':
            regenerative_at = now_utc + timedelta(seconds= frequency)
        else:
            # Handle unsupported frequency_type
            regenerative_at = None
        return regenerative_at


# ------------------------------------Regenrative Time Calculate -----------------------------------------------------------------

from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


#------------------------------------------------Get All Original Image Public TRUE---------------------------------------------

class GetPublicOriginalImage(APIView):
    pagination_class = PageNumberPagination  # Add pagination class
    def get(self, request):
        img = Image.objects.filter(public=True).order_by('-created')
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(img, request)
        orig_Image_history=[]
        for images in result_page:
            tmp = {
                'user' : images.user.email,
                'original_image' : str(images.photo),
                'public' : images.public,
                'original_at': images.created.strftime("%d/%m/%Y %H:%M:%S") if images.created else None,
            }
            orig_Image_history.append(tmp)

        jsonn_response = {
            'Original_Image_data' : orig_Image_history,
        }
        # response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # # Set the Referrer Policy header
        # response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # return response
        return paginator.get_paginated_response(jsonn_response)

#------------------------------------------------Get All Original Image Public TRUE-------------------------------------

#------------------------------------------------Get All Regenerative Image Public TRUE---------------------------------------------

class GetPublicRegenrativeImage(APIView):
    pagination_class = PageNumberPagination  # Add pagination class
    def get(self, request):
        img = RegeneratedImage.objects.filter(public=True).order_by('-created')
        # Apply pagination to the queryset
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(img, request)

        Regen_Image_history=[]
        for images in result_page:
            tmp = {
                'user' : images.user.email,
                'regenerated_image' : str(images.regenerated_image),
                'public' : images.public,
                'regenerated_at': images.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if images.regenerated_at else None,
            }
            Regen_Image_history.append(tmp)

        jsonn_response = {
            'Regenerated_Image_data' : Regen_Image_history,
        }
        # response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # # Set the Referrer Policy header
        # response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # return response
        return paginator.get_paginated_response(jsonn_response)

#------------------------------------------------Get All Regenerative Image Public TRUE-------------------------------------


#------------------------------------------------Get All Regenerative Image-------------------------------------------------

# class GetAllRegenrativeImage(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     @csrf_exempt
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)

#     def post(self,request):
#         Regen_Image_history = []
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()    
#         if not user:
#             return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
#         regen_count=0
#         for allregeneratedImage in RegeneratedImage.objects.filter(user=user):
#             tmp = {
#                 'user' : allregeneratedImage.user.email,
#                 'regenerated_image_id' : allregeneratedImage.id,
#                 'regenerated_image' : str(allregeneratedImage.regenerated_image),
#                 'original_image_id' : allregeneratedImage.original_image_id,
#                 'original_image_name' : allregeneratedImage.original_image_name,
#                 'public' : allregeneratedImage.public,
#                 # 'prompt' : allregeneratedImage.prompt,
#                 # 'frequency_type' : allregeneratedImage.frequency_type,#created.strftime("%d/%m/%Y"),
#                 # 'frequency' : allregeneratedImage.frequency,#json.loads(history.result.replace("'", "\"")),
#                 'created': allregeneratedImage.created.strftime("%d/%m/%Y %H:%M:%S"),
#                 'regenerated_at': allregeneratedImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allregeneratedImage.regenerated_at else None,
#                 'next_regeneration_at': allregeneratedImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
#             }
#             regen_count+=1
#             Regen_Image_history.append(tmp)

#         jsonn_response = {
#             'Total_Regenerated_Image_count' : regen_count,
#             'Regenerated_Image_data' : Regen_Image_history,
#             #'deposit_history' : diposit_history
#         }
#         response = Response(jsonn_response, status=status.HTTP_200_OK)
        
#         # Set the Referrer Policy header
#         response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

#         return response

class GetAllRegenrativeImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination  # Add pagination class

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)

        regenerated_images = RegeneratedImage.objects.filter(user=user).order_by('-created')

        # Apply pagination to the queryset
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(regenerated_images, request)

        Regen_Image_history = []
        for allregeneratedImage in result_page:
            tmp = {
                'user': allregeneratedImage.user.email,
                'regenerated_image_id': allregeneratedImage.id,
                'regenerated_image': str(allregeneratedImage.regenerated_image),
                'original_image_id': allregeneratedImage.original_image_id,
                'original_image_name': allregeneratedImage.original_image_name,
                'public': allregeneratedImage.public,
                'created': allregeneratedImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allregeneratedImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allregeneratedImage.regenerated_at else None,
                'next_regeneration_at': allregeneratedImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
            }
            Regen_Image_history.append(tmp)

        json_response = {
            'Regenerated_Image_count': paginator.page.paginator.count,
            'Regenerated_Image_data': Regen_Image_history,
        }
        # response = Response(json_response, status=status.HTTP_200_OK)

        # # Set the Referrer Policy header
        # response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # return response
    
        return paginator.get_paginated_response(json_response)





#------------------------------------------------Get All Regenerative Image-------------------------------------------------
    

#------------------------------------------------Get All Original Image-------------------------------------------------
# class GetAllOriginalImage(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     @csrf_exempt
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)
    
#     def post(self,request):
#         Original_Image_history = []
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()    
#         if not user:
#             return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
#         Original_count=0
#         for allOriginalImage in Image.objects.filter(user=user):
#             tmp = {
#                 'user' : allOriginalImage.user.email,
#                 'original_image_id' : allOriginalImage.id,
#                 'original_image_name' : allOriginalImage.image_name,
#                 'original_image': str(allOriginalImage.photo),
#                 'public' : allOriginalImage.public,
#                 'prompt' : allOriginalImage.prompt,
#                 # 'frequency_type' : allOriginalImage.frequency_type,#created.strftime("%d/%m/%Y"),
#                 # 'frequency' : allOriginalImage.frequency,#json.loads(history.result.replace("'", "\"")),
#                 'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
#                 'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
#                 'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
#             }
#             Original_count+=1
#             Original_Image_history.append(tmp)

#         jsonn_response = {
#             'Original_Image_count' : Original_count,
#             'Original_Image_data' : Original_Image_history,
#             #'deposit_history' : diposit_history
#         }
#         response = Response(jsonn_response, status=status.HTTP_200_OK)

#         # Set the Referrer Policy header
#         response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

#         return response
    

class GetAllOriginalImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self,request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    
        if not user:
            return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)

        original_images = Image.objects.filter(user=user).order_by('-created')
        
        # Paginate the queryset
        paginator = self.pagination_class()
        paginated_original_images = paginator.paginate_queryset(original_images, request)

        Original_Image_history = []
        for allOriginalImage in paginated_original_images:
            tmp = {
                'user': allOriginalImage.user.email,
                'original_image_id': allOriginalImage.id,
                'original_image_name': allOriginalImage.image_name,
                'original_image': str(allOriginalImage.photo),
                'public': allOriginalImage.public,
                'prompt': allOriginalImage.prompt,
                'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
                'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                'user_image_name':allOriginalImage.user_image_name,
                'tag':allOriginalImage.tag,
                'description':allOriginalImage.description
            }
            Original_Image_history.append(tmp)

        json_response = {
            'Total_Original_Image_count': paginator.page.paginator.count,
            'Original_Image_data': Original_Image_history,
        }

        return paginator.get_paginated_response(json_response)






#------------------------------------------------Get All Original Image-------------------------------------------------



#------------------------------------------------Get SINGLE Regenerative Image-------------------------------------------------

class GetOneRegenrativeImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    
        if not user:
            return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
        image_id=request.data.get('image_id')
        if not request.data.get('image_id') or not image_id:
            return Response({'Message': 'Image Id Not found'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            allregeneratedImage = RegeneratedImage.objects.filter(user=user,id=image_id).first()
            One_Regen_Image = {
                'user' : allregeneratedImage.user.email,
                'regenerated_image_id' : allregeneratedImage.id,
                'regenerated_image' : str(allregeneratedImage.regenerated_image),
                'original_image_id' : allregeneratedImage.original_image_id,
                'original_image_name' : allregeneratedImage.original_image_name,
                'public' : allregeneratedImage.public,
                # 'prompt' : allregeneratedImage.prompt,
                # 'frequency_type' : allregeneratedImage.frequency_type,#created.strftime("%d/%m/%Y"),
                # 'frequency' : allregeneratedImage.frequency,#json.loads(history.result.replace("'", "\"")),
                'created': allregeneratedImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allregeneratedImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allregeneratedImage.regenerated_at else None,
                'next_regeneration_at': allregeneratedImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
            }
                
                

            jsonn_response = {
                'Regenerated_Image_data' : One_Regen_Image,
                #'deposit_history' : diposit_history
            }
            response = Response(jsonn_response, status=status.HTTP_200_OK)
            # Set the Referrer Policy header
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
        
        except:
            jsonn_response = {
                'Message' : "No Images Found"
            }
            response = Response(jsonn_response, status=status.HTTP_400_BAD_REQUEST)
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
#------------------------------------------------Get SINGLE Regenerative Image-------------------------------------------------
    


#------------------------------------------------Get SINGLE Original Image-------------------------------------------------

class GetOneOriginalImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    
        if not user:
            return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
        image_id=request.data.get('image_id')
        if not request.data.get('image_id') or not image_id:
            return Response({'Message': 'image_id Not found'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:              
            allOriginalImage = Image.objects.filter(user=user,id=image_id).first()
            One_Original_Image = {
                'user' : allOriginalImage.user.email,
                'original_image_id' : allOriginalImage.id,
                'original_image_name' : allOriginalImage.image_name,
                'original_image': str(allOriginalImage.photo),
                'public' : allOriginalImage.public,
                'prompt' : allOriginalImage.prompt,
                'frequency_type' : allOriginalImage.frequency_type,#created.strftime("%d/%m/%Y"),
                'frequency' : allOriginalImage.frequency,#json.loads(history.result.replace("'", "\"")),
                'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
                'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                'user_image_name':allOriginalImage.user_image_name,
                'tag':allOriginalImage.tag,
                'description':allOriginalImage.description
            }

            jsonn_response = {
                'Original_Image_data' : One_Original_Image,
                #'deposit_history' : diposit_history
            }
            response = Response(jsonn_response, status=status.HTTP_200_OK)
            
            # Set the Referrer Policy header
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

            return response
        
        except:
            jsonn_response = {
                'Message' : "No Images Found"
            }
            response = Response(jsonn_response, status=status.HTTP_400_BAD_REQUEST)
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
#------------------------------------------------Get SINGLE Original Image-------------------------------------------------




# -----------------------------------------------ADMIN API's ---------------------------------------------------------------
from rest_framework.response import Response

class GetAllPayments(APIView):
    """ 
    Get-all-Payment if token is of super user
    """

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        all_payment = PaymentRecord.objects.all()

        payment_list=[]
        for payment in all_payment:
            payment_tmp={
            "Payment ID" :payment.id,
            "User Email" :payment.user.email,
            "Payment Amount" :payment.total_amount,
            "Total Credits" :payment.total_credits,
            "Payment time" :payment.date_time,
            "Payment Status" :payment.payment_status,
            "Payment Gateway ID" :payment.payment_id,
            "Payment Mode" :payment.payment_mode,
            } 

            payment_list.append(payment_tmp)
        
        if payment_list :
            return Response({'Message' : 'successfully got the payment list','Payment List' : payment_list}, status=status.HTTP_200_OK)
        return Response({'Message' : 'could not got the payment list'}, status=status.HTTP_204_NO_CONTENT)

class GetAllUsers(APIView):
    """ 
    Get-all-user if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        all_users = CustomUser.objects.all()
        total_users = len(all_users) 
        user_list=[]
        for users in all_users:
            users_tmp={
            "User ID" :users.id,
            "User Email" :users.email,
            "Name"  :users.name,
            #"Payment Amount" :users.total_amount,
            "Total Credits" :users.credit,
            "Registered on" :users.created.strftime("%d/%m/%Y %H:%M:%S"),
            "Verification Status" :users.is_user_verified,
            #"Payment Mode" :users.payment_mode,
            }

            user_list.append(users_tmp)

        jsonn_response = {
            'Total user' : total_users,
            'Users Data' : user_list
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response

        
        # if user_list :
        #     return Response({'Message' : 'successfully got the user data','User data' : response}, status=status.HTTP_200_OK)
        # return Response({'Message' : 'could not got the user list'}, status=status.HTTP_204_NO_CONTENT)



class DeleteUser(APIView):
    """ 
    Delete-user if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_deleted = False

        if 'email' not in request.data or not request.data.get('email'):
            return Response({'Message' : 'could not got the user, Please provide email'}, status=status.HTTP_204_NO_CONTENT)
        
        delete_user_email =request.data['email']
        delete_user = CustomUser.objects.filter(email=delete_user_email).first()  

        if not delete_user:
            msg = 'User not in record!!'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        # delete_user.delete()
        if delete_user.delete() :
            user_deleted = True
            return Response({'Message' : 'successfully got the user deleted', 'user_deleted' : user_deleted}, status=status.HTTP_200_OK) 
        
        return Response({'Message' : 'could not delete the user', 'user_deleted' : user_deleted}, status=status.HTTP_400_BAD_REQUEST)
 



class ViewUser(APIView):
    """ 
    Get-user-Details if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        
        if 'email' not in request.data or not request.data.get('email'):
            return Response({'Message' : 'could not got the user, please provide email'}, status=status.HTTP_204_NO_CONTENT)
        
        user_email =request.data.get('email')
        # User Table
        user_ = CustomUser.objects.filter(email=user_email).first()
        if not user_:
            msg = 'User not in record!!'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        print("The user is :",user_)
        users_tmp={
            #"Payment ID" :user_.id,
            "User Email" :user_.email,
            "User Name"  :user_.name,
            "Total Credits" :user_.credit,
            "Registered on" :user_.created.strftime("%d/%m/%Y %H:%M:%S"),
            "Verification Status" :user_.is_user_verified,
            "Stripe Customer ID": user_.stripe_customer_id,
            "Membership Name" : str(user_.membership) if user_.membership else None,
            "Membership ID" : user_.membership.id if user_.membership else None,
            "Membership Expiry" : user_.membership_expiry.strftime("%d/%m/%Y %H:%M:%S") if user_.membership_expiry else None,
        }

        # Payment Table
        payments = PaymentRecord.objects.filter(user=user_).order_by('-date_time')
        pay_lst=[]

        if payments:
            for payment in payments:
                payment_tmp={
                    "Payment ID" :payment.id,
                    "User Email" :payment.user.email,
                    "Payment Amount" :str(payment.total_amount),
                    "Total Credits" :payment.total_credits,
                    "Payment date time" :payment.date_time.strftime("%d/%m/%Y %H:%M:%S"),
                    "Payment Status" :payment.payment_status,
                    "Payment Gateway ID" :payment.payment_id,
                    "Payment Mode" :payment.payment_mode,
                    }
                pay_lst.append(payment_tmp)


        # Credit Table
        credit_ = CreditHistory.objects.filter(user=user_).order_by('-date_time')
        cred_lst=[]

        if credit_:
            for credit in credit_:
                credit_tmp={
                    "credit ID" :credit.id,
                    "User Email" :credit.user.email,
                    "Total Credits Deducted" :credit.total_credits_deducted,
                    "Transaction Type" :credit.type_of_transaction,
                    "Transaction Date Time" :credit.created.strftime("%d/%m/%Y %H:%M:%S"),
                    "Payment ID" :credit.payment_id,
                    "Description" :credit.description,
                    }
                cred_lst.append(credit_tmp)


        # Original Image Table
        imgs = Image.objects.filter(user=user_).order_by('-updated')
        img_lst=[]
        if imgs:
            for img in imgs:
                One_Original_Image = {
                        'original_image_id' : img.id,
                        'user' : img.user.email,
                        'original_image_name' : img.image_name,
                        'original_image': str(img.photo),
                        'public' : img.public,
                        'prompt' : img.prompt,
                        'created': img.created.strftime("%d/%m/%Y %H:%M:%S"),
                        'regenerated_at': img.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if img.regenerated_at else None,
                        'next_regeneration_at': img.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                    }
                img_lst.append(One_Original_Image)


        # Regenerated Image Table
        regen_imgs = RegeneratedImage.objects.filter(user=user_).order_by('-updated')
        regen_imgs_lst=[]
        if regen_imgs:
            for regen_img in regen_imgs:
                One_Regen_Image = {
                        'regenerated_image_id' : regen_img.id,
                        'user' : regen_img.user.email,
                        'regenerated_image' : str(regen_img.regenerated_image),
                        'original_image_id' : regen_img.original_image_id,
                        'original_image_name' : regen_img.original_image_name,
                        'public' : regen_img.public,
                        'created': regen_img.created.strftime("%d/%m/%Y %H:%M:%S"),
                        'regenerated_at': regen_img.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if regen_img.regenerated_at else None,
                        'next_regeneration_at': regen_img.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                    }
                regen_imgs_lst.append(One_Regen_Image)
        

        jsonn_response = {
            'user_data' : users_tmp,
            'Original_Image_data' : img_lst,
            'Regenerated_Image_data' : regen_imgs_lst,
            'Credit_data' : cred_lst,
            'Payment_data' : pay_lst,
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response


        #return Response({'Message' : 'could not find the user details'}, status=status.HTTP_400_BAD_REQUEST)
 

class AdminUpdateUser(APIView):
    """ 
    Update-user-details if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_found = False
        if 'email' not in request.data or not request.data.get('email'):
            msg = 'could not found the email'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
        
        # if not 'feild' in request.data or not request.data['feild']:
        #     msg = 'could not found the feild which needs to be edited'
        #     return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
        
        if not 'new_name' in request.data or not request.data['new_name']:
            msg = 'could not found the new name which needs to be replaced with old name'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
            
        found_user = CustomUser.objects.filter(is_superuser=False,email=request.data['email'])
        if not found_user :
            return Response({'Message' : 'could not got the user'}, status=status.HTTP_204_NO_CONTENT)

        found_user = found_user.first()
        #field_name = request.data['feild']
        new_name = request.data['new_name']
        
        # if field_name != 'name':
        #     return Response({'Message' : 'Field name must be "name"'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            setattr(found_user, "name", new_name)
            found_user.save()
            msg = 'Successfully edited the user data'
            status_code = status.HTTP_200_OK
            
        except Exception as e:
            msg = f'Error editing user data: {str(e)}'
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response({'Message' : msg}, status=status_code)




class AdminGetAllRegenrativeImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination 

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        Regen_Image_history = []  
        regen_count=0

        all_regen = RegeneratedImage.objects.all().order_by('-created')

        # Apply pagination to the queryset
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(all_regen, request)

        for allregeneratedImage in result_page:
            tmp = {
                'user' : allregeneratedImage.user.email,
                'regenerated_image_id' : allregeneratedImage.id,
                'regenerated_image' : str(allregeneratedImage.regenerated_image),
                'original_image_id' : allregeneratedImage.original_image_id,
                'original_image_name' : allregeneratedImage.original_image_name,
                'public' : allregeneratedImage.public,
                'created': allregeneratedImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allregeneratedImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allregeneratedImage.regenerated_at else None,
                'next_regeneration_at': allregeneratedImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
            }
            regen_count+=1
            Regen_Image_history.append(tmp)

        jsonn_response = {
            'Total_Regenerated_Image_count' : paginator.page.paginator.count,
            'Regenerated_Image_data' : Regen_Image_history,
            #'deposit_history' : diposit_history
        }
        # response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # # Set the Referrer Policy header
        # response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # return response

        return paginator.get_paginated_response(jsonn_response)




class AdminGetAllOriginalImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination 

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        Original_Image_history = []
        Original_count=0

        all_img = Image.objects.all().order_by('-created')

        # Apply pagination to the queryset
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(all_img, request)

        for allOriginalImage in result_page:
            tmp = {
                'user' : allOriginalImage.user.email,
                'original_image_id' : allOriginalImage.id,
                'original_image_name' : allOriginalImage.image_name,
                'original_image': str(allOriginalImage.photo),
                'public' : allOriginalImage.public,
                'prompt' : allOriginalImage.prompt,
                'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
                'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                'user_image_name':allOriginalImage.user_image_name,
                'tag':allOriginalImage.tag,
                'description':allOriginalImage.description
            }
            Original_count+=1
            Original_Image_history.append(tmp)

        jsonn_response = {
            'Total_Original_Image_count' : paginator.page.paginator.count,#Original_count,
            'Original_Image_data' : Original_Image_history,
        }
        # response = Response(jsonn_response, status=status.HTTP_200_OK)

        # # Set the Referrer Policy header
        # response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # return response
    
        return paginator.get_paginated_response(jsonn_response)



#------------------------------------------------ ADMIN Get SINGLE Regenerative Image-------------------------------------------------

class AdminGetOneRegenrativeImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED) 
   
        if 'image_id' not in request.data or not request.data.get('image_id'):
            return Response({'Message': 'Image Id Not found'}, status=status.HTTP_400_BAD_REQUEST)
        
        image_id=request.data.get('image_id')

        try:
            allregeneratedImage = RegeneratedImage.objects.filter(id=image_id).first()
            One_Regen_Image = {
                'user' : allregeneratedImage.user.email,
                'regenerated_image_id' : allregeneratedImage.id,
                'regenerated_image' : str(allregeneratedImage.regenerated_image),
                'original_image_id' : allregeneratedImage.original_image_id,
                'original_image_name' : allregeneratedImage.original_image_name,
                'public' : allregeneratedImage.public,
                'created': allregeneratedImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allregeneratedImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allregeneratedImage.regenerated_at else None,
                'next_regeneration_at': allregeneratedImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
            }
                
                

            jsonn_response = {
                'Regenerated_Image_data' : One_Regen_Image,
                #'deposit_history' : diposit_history
            }
            response = Response(jsonn_response, status=status.HTTP_200_OK)
            # Set the Referrer Policy header
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
        
        except:
            jsonn_response = {
                'Message' : "No Images Found"
            }
            response = Response(jsonn_response, status=status.HTTP_400_BAD_REQUEST)
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
#------------------------------------------------ ADMIN Get SINGLE Regenerative Image-------------------------------------------------
    


#------------------------------------------------ ADMIN Get SINGLE Original Image-------------------------------------------------

class AdminGetOneOriginalImage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)

        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        if 'image_id' not in request.data or not request.data.get('image_id'):
            #image_id=request.data.get('image_id')
            return Response({'Message': 'Image Id Not found'}, status=status.HTTP_400_BAD_REQUEST)
        image_id=request.data.get('image_id')
        print(image_id)
        
        try:              
            allOriginalImage = Image.objects.filter(id=image_id).first()
            One_Original_Image = {
                'user' : allOriginalImage.user.email,
                'original_image_id' : allOriginalImage.id,
                'original_image_name' : allOriginalImage.image_name,
                'original_image': str(allOriginalImage.photo),
                'public' : allOriginalImage.public,
                'prompt' : allOriginalImage.prompt,
                'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
                'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
                'user_image_name':allOriginalImage.user_image_name,
                'tag':allOriginalImage.tag,
                'description':allOriginalImage.description
            }

            jsonn_response = {
                'Original_Image_data' : One_Original_Image,
            }
            response = Response(jsonn_response, status=status.HTTP_200_OK)
            
            # Set the Referrer Policy header
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

            return response
        
        except:
            jsonn_response = {
                'Message' : "No Images Found"
            }
            response = Response(jsonn_response, status=status.HTTP_400_BAD_REQUEST)
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            return response
#------------------------------------------------ ADMIN Get SINGLE Original Image-------------------------------------------------

#------------------------------------------------ ADMIN Analytics-------------------------------------------------
class AdminAnalytics(APIView):
    """ 
    Get-Analytics if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        # User Table
        user_ = CustomUser.objects.all()
        total_user = len(user_)

        # Payment Table
        payment = PaymentRecord.objects.all()
        total_payment_count = len(payment)

        tot_pay=0
        if payment:
            for pay in payment:
                tot_pay = tot_pay + pay.total_amount
        

        # Credit Table
        # credit = CreditHistory.objects.all()
        # if credit:
        #     credit_tmp={
        #         "credit ID" :credit.id,
        #         "User Email" :credit.user.email,
        #         "Total Credits" :credit.total_credits,
        #         "Transaction Type" :credit.type_of_transaction,
        #         "Transaction Date" :credit.created.strftime("%d/%m/%Y"),
        #         "Payment ID" :credit.payment_id,
        #         "Description" :credit.description,
        #         }

        # credit_tmp={}

        # Original Image Table
        img = Image.objects.all()
        total_original_image = len(img)

        # Regenerated Image Table
        regen_img = RegeneratedImage.objects.all()
        total_regen_image = len(regen_img)

        jsonn_response = {
            'Total user' : total_user,
            'Total Original Images' : total_original_image,
            'Total Regenerated Images' : total_regen_image,
            'Total Payments' : total_payment_count,
            'Total Payment Amount' : tot_pay,
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response

#------------------------------------------------ ADMIN Analytics-------------------------------------------------


# -----------------------------------------------ADMIN Delete Original Image ---------------------------------------------------------------
class DeleteImageAdmin(APIView):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        try:
            user_id = get_user_id_from_token(request)
            user, is_superuser = IsSuperUser(user_id)
            if not user or not is_superuser:
                msg = 'could not found the super user'
                return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

            if 'image_id' not in request.data or not request.data.get('image_id'):
                return JsonResponse({'Message': 'Image ID not found'}, status=404) 
            
            error_messages = []

            image_ids = request.data.get('image_id',[])
            print("The Image IDs are: ",image_ids)
            for image_id in image_ids:
                try:
                    image = Image.objects.get(id=image_id)
                    image_name=image.image_name
                    user_of_image = image.user
                    # Delete the image file from the S3 bucket
                    #s3_key = str(image.photo)
                    s3_key = str(image.image_name)+".jpg"
                    orig_imge_id=image.id
                    print('The original Image S3 Key is: ',s3_key)

                    
        # ----------------------------------------Delete Regenerated Image From S3 Upon Deleteion of Original Image----------------------------------
                    # Fetch and delete the corresponding regenerated image from the S3 bucket
                    regenerated_image = RegeneratedImage.objects.filter(original_image_id=orig_imge_id)
                    if regenerated_image:
                        regenerated_s3_key = str(regenerated_image[0].original_image_name)+'.png'
                        print("The regenerated Image S3 Key is :",regenerated_s3_key)
                        # Delete from the regenerated image bucket
                        regenerated_bucket = settings.AWS_STORAGE_BUCKET_NAME2
                        #regenerated_storage = get_storage_class()(bucket=regenerated_bucket)
                        regenerated_storage = get_storage_class("storages.backends.s3boto3.S3Boto3Storage")()
                        regenerated_storage.bucket_name = regenerated_bucket
                        regenerated_storage.delete(regenerated_s3_key)
                        print(" THE REGENERATED IMAGE HAS BEEN DELETD",str(regenerated_image[0].original_image_name))

        # ----------------------------------------Delete Regenerated Image From S3 Upon Deleteion of Original Image----------------------------------


                    default_storage.delete(s3_key)

                    History.objects.create(
                        tag='admin-delete',
                        user=user_of_image,
                        image_data=image.photo,
                        prompt=image.prompt,
                        frequency_type=image.frequency_type,
                        frequency=image.frequency,
                        public=image.public,
                        image_name=image_name
                    )

                    # s3_key = image.image_name +'.png'  Regenerated Image



                    image.delete()
                except ObjectDoesNotExist:
                    error_messages.append(f'Image with ID {image_id} not found or have some error.')
                    print(f'Image with ID {image_id} not found or have some error.')
                except ClientError as e:
                    error_messages.append(f'Error deleting image with ID {image_id}: {str(e)}')
                    print(f'Error deleting image with ID {image_id}: {str(e)}')
                except Exception as e:
                    error_messages.append(f'An error occurred with image ID {image_id}: {str(e)}')
                    print(f'An error occurred with image ID {image_id}: {str(e)}')
            
            if len(error_messages)==0:

                return JsonResponse({'Message': 'Image deleted successfully.'}, status=status.HTTP_200_OK)
            else:
                return JsonResponse({'Message': 'Some images deleted successfully, But some selected image id are wrong'}, status=status.HTTP_400_BAD_REQUEST)
                

            # return JsonResponse({'Message': 'Image deleted successfully.'})
            # else:
            #     return JsonResponse({'Message': 'Image not found.'}, status=404)
        except Image.DoesNotExist:
            return JsonResponse({'Message': 'Image not found.'}, status=404)
        except ClientError as e:
            return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)
        except Exception as e:
            return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)

# -----------------------------------------------ADMIN Delete Original Image ---------------------------------------------------------------

# -----------------------------------------------ADMIN Add Credit To user ---------------------------------------------------------------

class AdminAddCredit(APIView):
    """ 
    Update-user-Credit if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_found = False
        if 'user_id' not in request.data or not request.data.get('user_id'):
            msg = 'could not found the user_id'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
        
        if not 'credit_amount' in request.data or not request.data['credit_amount']:
            msg = 'could not found the credit_amount to add credit to user'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
            
        found_user = CustomUser.objects.filter(is_superuser=False,id=request.data['user_id']).first()
        if not found_user :
            return Response({'Message' : 'could not got the user'}, status=status.HTTP_204_NO_CONTENT)

        # found_user = found_user
        try:
            credits_amount = int(request.data['credit_amount'])
        except:
            return Response({'Message' : 'credit amount given is not proper'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        try:
            if credits_amount <= 0:
                return Response({'Message' : 'Credit amount must be a positive number'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValueError as e:
            error_message = str(e)
            return Response({'Message': error_message}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            credit_balance_before_update = found_user.credit
            email_user=found_user.email
            found_user.credit=found_user.credit + credits_amount
            found_user.save()
            msg = 'Successfully add credits to the user'
            status_code = status.HTTP_200_OK

            credit_balance_left = found_user.credit

# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            
            deduction_description = f"Added '{credits_amount}' credit to the user '{email_user}'"
            CreditHistory.objects.create(
                user=found_user,
                total_credits_deducted=credits_amount,
                type_of_transaction="Credit Addition",
                date_time=datetime.now(pytz.utc),
                payment_id="admin",  # You can leave this blank for credit deductions
                description=deduction_description,
                credit_balance_left=credit_balance_left
            )
# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            return Response({'Message' : msg, 'email': email_user, 'credit_balance_before_update':credit_balance_before_update, 'updated_credit_balance':credit_balance_left}, status=status_code)
            
        except Exception as e:
            msg = f'Error Occured while adding credit to user: {str(e)}'
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response({'Message' : msg, 'email': email_user}, status=status_code)

# -----------------------------------------------ADMIN Add Credit To user ---------------------------------------------------------------



# -----------------------------------------------ADMIN Deduct Credit from user ---------------------------------------------------------------

class AdminDeductCredit(APIView):
    """ 
    Update-user-Credit if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_found = False
        if 'user_id' not in request.data or not request.data.get('user_id'):
            msg = 'could not found the user_id'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
        
        if not 'credit_amount' in request.data or not request.data['credit_amount']:
            msg = 'could not found the credit_amount to add credit to user'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
            
        found_user = CustomUser.objects.filter(is_superuser=False,id=request.data['user_id']).first()
        if not found_user :
            return Response({'Message' : 'could not got the user'}, status=status.HTTP_204_NO_CONTENT)

        # found_user = found_user
        try:
            credits_amount = int(request.data['credit_amount'])
        except:
            return Response({'Message' : 'credit amount given is not proper'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        try:
            if credits_amount <= 0:
                return Response({'Message' : 'Credit amount must be a positive number'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValueError as e:
            error_message = str(e)
            return Response({'Message': error_message}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            credit_balance_before_update = found_user.credit
            email_user=found_user.email
            if credits_amount > found_user.credit:
                found_user.credit = 0
            else:
                found_user.credit=found_user.credit - credits_amount
            found_user.save()
            msg = 'Successfully deducted credits to the user'
            status_code = status.HTTP_200_OK

            credit_balance_left = found_user.credit

# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            
            deduction_description = f"Deducted '{credits_amount}' credit from the user '{email_user}'"
            CreditHistory.objects.create(
                user=found_user,
                total_credits_deducted=credits_amount,
                type_of_transaction="Credit Deduction",
                date_time=datetime.now(pytz.utc),
                payment_id="admin",  # You can leave this blank for credit deductions
                description=deduction_description,
                credit_balance_left=credit_balance_left
            )
# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            return Response({'Message' : msg, 'email': email_user, 'credit_balance_before_update':credit_balance_before_update, 'updated_credit_balance':credit_balance_left}, status=status_code)
            
        except Exception as e:
            msg = f'Error Occured while deducting credit to user: {str(e)}'
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response({'Message' : msg, 'email': email_user}, status=status_code)

# -----------------------------------------------ADMIN Deduct Credit from user ---------------------------------------------------------------





# -----------------------------------------------ADMIN API's ---------------------------------------------------------------

#----------------------Code copied from Keywordlit Project--------------------------------------------------------------
from django.core.files.temp import NamedTemporaryFile
import tempfile
class UploadImageView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    # def get(self, request, *args, **kwargs):
    #     # Your get method logic here
    #     # You can include the CSRF token in the response if needed
    #     return super().get(request, *args, **kwargs)


    def post(self, request):
        mutable_post = request.POST.copy()

        if 'photo' in request.FILES:
            form = ImageForm(request.POST, request.FILES)
        elif 'photo_url' in request.data:
            # Download the image from the provided URL and create a temporary file
            # photo_url = request.data['photo_url']
            # try:
            #     response = requests.get(photo_url, stream=True)
            #     response.raise_for_status()
            # except requests.exceptions.RequestException as e:
            #     return JsonResponse({'Message': f'Failed to fetch image from URL: {str(e)}'}, status=400)
            
            photo_url = request.data['photo_url']
            try:
                res = requests.head(photo_url)
                content_length = res.headers.get('content-length')
                if content_length and int(content_length) > int(f'{settings.MAX_IMAGE_SIZE_MB}') * 1024 * 1024:  # Check if size exceeds 20 MB
                    return JsonResponse({'Message': f'Image exceeds the {settings.MAX_IMAGE_SIZE_MB} MB limit!'}, status=400)
                else:
                    response = requests.get(photo_url, stream=True)
                    response.raise_for_status()
                    # Proceed with your code for handling the image
            except requests.exceptions.RequestException as e:
                return JsonResponse({'Message': f'Failed to fetch image from URL: {str(e)}'}, status=400)

            # Create a temporary file to save the downloaded image
            img_temp = tempfile.NamedTemporaryFile(delete=False)
            # img_temp = NamedTemporaryFile(delete=False)
            img_temp.write(response.content)
            img_temp.flush()
            photo = None

            mutable_post['photo'] = img_temp
            form = ImageForm(mutable_post, request.FILES)

            # Create dummy POST data with 'photo' field set to the downloaded image file
            # request.POST = request.POST.copy()
            # request.FILES = {'photo': img_temp}
            # form = ImageForm(request.POST, request.FILES)
        else:
            return JsonResponse({'Message': 'No valid image provided.'}, status=400)


        # form = ImageForm(request.POST, request.FILES)
        if form.is_valid():
            # Set the user before saving the form
            user_id = get_user_id_from_token(request)
            user = CustomUser.objects.filter(id=user_id).first()
            if not user:
                return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)

            if user.credit < 1:
                msg = 'Insufficient credit to perform this action.'
                return Response({"Message": msg}, status=status.HTTP_402_PAYMENT_REQUIRED)

            print("the user is: ",user.email)
            # Retrieve the uploaded file from request.FILES
            # photo = request.FILES.get('photo')
            # if not photo:
            #     return JsonResponse({'Message': 'No file uploaded'}, status=400)
            print("The request with all the parameter are :",request.data)
            print("The request with POST AND ALL the parameter are :",request.POST)
            form.instance.user = user
            print("form.instance.user :",form.instance.user)
            frequency = form.cleaned_data.get('frequency')
            prompt = form.cleaned_data.get('prompt')
            frequency_type = form.cleaned_data.get('frequency_type')
            #photo = form.cleaned_data.get('photo')
            public = form.cleaned_data.get('public')

            user_image_name = form.cleaned_data.get('user_image_name')
            tag = form.cleaned_data.get('tag')
            description = form.cleaned_data.get('description')
#------------------------------------NEW PHOTO FIELD------------------------------------------------------------------
            print('The erro might be in here')
            #photo_url = request.data['photo_url']
            photo_url = request.data.get('photo_url', None)
            print('Photo URL : ',photo_url)
            photo = form.cleaned_data['photo']
            print('The erro might be up here')
#------------------------------------NEW PHOTO FIELD------------------------------------------------------------------
            print("The details are as follows for image upload")
            print("frequency:", frequency) 
            print("prompt:", prompt)
            print("frequency_type:", frequency_type)
            print("photo:", photo)
            print("public:", public)
            print("user_image_name:", user_image_name)
            print("tag:", tag)
            print("description:", description)
    
            max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
                # Check if the size of the uploaded image is less than or equal to the maximum size limit
            if photo_url is None:
                if photo.size > max_size:
                    return JsonResponse({'Message': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=400)


            # Calculate next regeneration datetime
            next_regeneration_at = calculate_regeneration_time(frequency, frequency_type)
            image_name=generate_random_string(15)
            # Save the image file to S3 with the desired file name
            file_name = f"{image_name}.jpg"  # Assuming the image format is JPG
            if photo_url:
                file_path = default_storage.save(file_name, img_temp) # It should be a string so we can split it to our need
            else:
                file_path = default_storage.save(file_name, photo)
            print("The file path is : ",file_path)

            # Get the URL using the storage backend
            original_image_url = default_storage.url(file_name)
            print('The original image url is :',original_image_url)

            edit_url=original_image_url.split('?')[0]
            print('The Edited url is :',edit_url)
            
            # Save the form data
            image_instance = form.save(commit=False)
            image_instance.nextregeneration_at = next_regeneration_at
            image_instance.image_name=image_name
            image_instance.photo=edit_url #file_path
            image_instance.save()
            


            History.objects.create(
                tag='create',
                user=user,
                image_data=edit_url,
                prompt=prompt,
                frequency_type=frequency_type,
                frequency=frequency,
                public=public,
                image_name=image_name
            )

# # --------------------------CODE For Regenrative Logic------------------------------------------------------------------

            # Regenerate and save to S3
            regen_image_url = self.regenerate_image_logic(image_instance)

            # Calculate the regenerative_at datetime based on frequency and frequency_type
            regenerative_at_ = calculate_regeneration_time(image_instance.frequency,image_instance.frequency_type)

            self.save_to_s3(regen_image_url, image_instance, user, regenerative_at_)

            # Deduct User Credit
            user.credit= user.credit - 1
            user.save()
# # --------------------------CODE For Regenrative Logic------------------------------------------------------------------

            credit_balance_left = user.credit
# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            # Record the credit deduction history
            deduction_description = f"Deducted 1 credit for regenerating image '{image_name}'"
            CreditHistory.objects.create(
                user=user,
                total_credits_deducted=1,
                type_of_transaction="Credit Deduction",
                date_time=datetime.now(pytz.utc),
                payment_id="",  # You can leave this blank for credit deductions
                description=deduction_description,
                credit_balance_left=credit_balance_left
            )
# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
            # Clean up temporary file if exists
            if 'img_temp' in locals() and hasattr(img_temp, 'name') and os.path.exists(img_temp.name):
                img_temp.close()
                os.unlink(img_temp.name)
            #form.save()
            #return redirect('/api/dashboard/')
            return JsonResponse({'Message': 'Image Upload successful.'})
        else:
            if 'img_temp' in locals() and hasattr(img_temp, 'name') and os.path.exists(img_temp.name):
                img_temp.close()  # Close the file handle
                os.unlink(img_temp.name)  # Delete the temporary file
                print("Temporary Image deleted")
            print("Form is invalid")
            print(form.errors)
            return JsonResponse({'Message': 'Image Upload Unsuccessful.'}, status=400)

    #--------------------------------------------Regenerating Image Logic ---------------------------------------------------------

    def preprocess_image(self, image_path, target_size=(1024, 1024)):
        from PIL import Image
        import io
        print("Hi, I am here")
        # # Open the image file
        # with Image.open(image_path) as img:
        #     # Convert image to RGBA mode
        #     img = img.convert("RGBA")
        #     # Resize the image
        #     resized_img = img.resize(target_size)
        #     # Create a BytesIO object to store the image data
        #     img_byte_array = io.BytesIO()
        #     # Save the image to the BytesIO object in PNG format
        #     resized_img.save(img_byte_array, format="PNG")
        #     # Get the bytes from the BytesIO object
        #     processed_image = img_byte_array.getvalue()

        print("Downloading image from:", image_path)
        # Download the image from the URL
        response = requests.get(image_path)
        if response.status_code != 200:
            raise Exception("Failed to download image")

        # Open the downloaded image
        with Image.open(io.BytesIO(response.content)) as img:
            # Convert image to RGBA mode
            img = img.convert("RGBA")
            # Resize the image
            resized_img = img.resize(target_size)
            # Create a BytesIO object to store the image data
            img_byte_array = io.BytesIO()
            # Save the image to the BytesIO object in PNG format
            resized_img.save(img_byte_array, format="PNG")
            # Get the bytes from the BytesIO object
            processed_image = img_byte_array.getvalue()
        return processed_image



    def generate_image(self, image_path):
        # Preprocess the image
        openai_api_key=openai_account.objects.first()
        api_key=openai_api_key.key
        preprocessed_image = self.preprocess_image(image_path)
        client = OpenAI(api_key=api_key)
        response = client.images.create_variation(
        image=preprocessed_image,
        n=2,
        size="1024x1024"
        )

        generated_image_url = response.data[0].url

        return generated_image_url


    def regenerate_image_logic(self, original_image):
        image_path=str(original_image.photo)
        regenerated_image_url = self.generate_image(image_path)
        return  regenerated_image_url

    def save_to_s3(self, image_url, original_image, user, regenerative_at_):
        s3 = boto3.client('s3', aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        original_image_name = original_image.image_name

        # Download the image data from the URL
        image_data = requests.get(image_url).content

        # Upload the binary data to your S3 bucket
        file_path = f'{original_image_name}.png'
        s3.put_object(Body=image_data, 
                    Bucket=settings.AWS_STORAGE_BUCKET_NAME2, 
                    Key=file_path,
                    ContentType='image/png',  
                    ContentDisposition='inline')

        s3_base_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME2}.s3.amazonaws.com/"
        regenerated_image_url = s3_base_url + file_path

        regenerated_image = RegeneratedImage.objects.create(
            user=user,
            original_image_name=original_image_name,
            original_image_id=original_image.id,
            regenerated_image=regenerated_image_url,
            regenerated_at=datetime.now(pytz.utc),
            public=original_image.public,
            nextregeneration_at=regenerative_at_,
            original_image_key_id=original_image  # Set the foreign key
        )

        original_image.regenerated_at = datetime.now(pytz.utc)
        original_image.nextregeneration_at = regenerative_at_
        original_image.save()

                

#--------------------------------------------Regenerating Image Logic ---------------------------------------------------------




from django.contrib.auth.decorators import login_required
from django.core.files.storage import get_storage_class


class DeleteImageView(APIView):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        try:
            user_id = get_user_id_from_token(request)
            if user_id:
                if 'image_id' not in request.data or not request.data.get('image_id'):
                    return JsonResponse({'Message': 'Image not found'}, status=404)
                
                error_messages = []

                image_id = request.data.get("image_id", [])

                # image_id = request.data.get("image_id")
                for images in image_id:
                    try:
                        user = CustomUser.objects.filter(id=user_id).first()
                        image = Image.objects.get(id=images, user=user)
                        image_name = image.image_name
                        #s3_key = str(image.photo)
                        s3_key = str(image.image_name)+".jpg"
                        orig_imge_id=image.id
                        print('The original Image S3 Key is: ',s3_key)

                        
        # ----------------------------------------Delete Regenerated Image From S3 Upon Deleteion of Original Image----------------------------------
                        # Fetch and delete the corresponding regenerated image from the S3 bucket
                        regenerated_image = RegeneratedImage.objects.filter(original_image_id=orig_imge_id)
                        if regenerated_image:
                            regenerated_s3_key = str(regenerated_image[0].original_image_name)+'.png'
                            print("The regenerated Image S3 Key is :",regenerated_s3_key)
                            # Delete from the regenerated image bucket
                            regenerated_bucket = settings.AWS_STORAGE_BUCKET_NAME2
                            #regenerated_storage = get_storage_class()(bucket=regenerated_bucket)
                            regenerated_storage = get_storage_class("storages.backends.s3boto3.S3Boto3Storage")()
                            regenerated_storage.bucket_name = regenerated_bucket
                            regenerated_storage.delete(regenerated_s3_key)
                            print(" THE REGENERATED IMAGE HAS BEEN DELETD",str(regenerated_image[0].original_image_name))

        # ----------------------------------------Delete Regenerated Image From S3 Upon Deleteion of Original Image----------------------------------


                        default_storage.delete(s3_key)

                        History.objects.create(
                            tag='delete',
                            user=user,
                            image_data=image.photo,
                            prompt=image.prompt,
                            frequency_type=image.frequency_type,
                            frequency=image.frequency,
                            public=image.public,
                            image_name=image_name
                        )

                        # s3_key = image.image_name +'.png'  Regenerated Image

                        image.delete()
                    except ObjectDoesNotExist:
                        error_messages.append(f'Image with ID {images} not found or have some error.')
                        print(f'Image with ID {images} not found or have some error.')
                    except ClientError as e:
                        error_messages.append(f'Error deleting image with ID {images}: {str(e)}')
                        print(f'Error deleting image with ID {images}: {str(e)}')
                    except Exception as e:
                        error_messages.append(f'An error occurred with image ID {images}: {str(e)}')
                        print(f'An error occurred with image ID {images}: {str(e)}')
                
                if len(error_messages)==0:

                    return JsonResponse({'Message': 'Image deleted successfully.'}, status=status.HTTP_200_OK)
                else:
                    return JsonResponse({'Message': 'Some images deleted successfully, But some selected image id are wrong'}, status=status.HTTP_400_BAD_REQUEST)
                # else:
                #     return JsonResponse({'Message': 'Image file not found in S3.'}, status=404)
            else:
                return JsonResponse({'Message': 'User Details not found.'}, status=403)
        except ObjectDoesNotExist:
            return JsonResponse({'Message': 'Image or User not found.'}, status=404)
        except ClientError as e:
            return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)
        except Exception as e:
            return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)






#@method_decorator(csrf_exempt, name='dispatch')
class UpdateImageView(View):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        image_id = request.POST.get('image_id')
        user_id = get_user_id_from_token(request)
        if user_id:
            if not 'image_id' in request.POST or not request.POST.get('image_id'):
                return JsonResponse({'Message': 'Image not found'}, status=404)
            try:
                user = CustomUser.objects.filter(id=user_id).first()
                if not user:
                    return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
                image = Image.objects.get(id=image_id, user=user)
                image_name=image.image_name
                # Update image details
                if 'frequency' in request.POST:
                    image.frequency = request.POST['frequency']
                if 'prompt' in request.POST:
                    image.prompt = request.POST['prompt']
                if 'frequency_type' in request.POST:
                    image.frequency_type = request.POST['frequency_type']
                if 'public' in request.POST:
                    image.public = request.POST['public']
                
                if 'tag' in request.POST:
                    image.tag = request.POST['tag']
                
                if 'description' in request.POST:
                    image.description = request.POST['description']
                
                if 'user_image_name' in request.POST:
                    image.user_image_name = request.POST['user_image_name']

                # Check if a new image file is provided
                new_image_data = request.FILES.get('photo')
                if new_image_data:

                    max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
                    # Check if the size of the uploaded image is less than or equal to the maximum size limit
                    if new_image_data.size > max_size:
                        return JsonResponse({'Message': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=400)
                    image.photo.save(image.image_name +'.jpg', new_image_data, save=True)
                    #image.save()
                    
                # Calculate next regeneration datetime if both frequency and frequency_type are provided
                if 'frequency' in request.POST and 'frequency_type' in request.POST:
                    next_regeneration_at = calculate_regeneration_time(image.frequency, image.frequency_type)
                    image.nextregeneration_at = next_regeneration_at
                # Save the updated image object
                History.objects.create(
                    tag='update',
                    user=user,
                    image_data=image.photo,
                    prompt=image.prompt,
                    frequency_type=image.frequency_type,
                    frequency=image.frequency,
                    public=image.public,
                    image_name=image_name)
                s3_base_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/"
                edit_image_url = s3_base_url + image.image_name +'.jpg'
                image.photo = edit_image_url
                image.save()

                return JsonResponse({'Message': 'Image details updated successfully.'})
            
            except Image.DoesNotExist:
                return JsonResponse({'Message': 'Image not found.'}, status=404)
            except CustomUser.DoesNotExist:
                return JsonResponse({'Message': 'User not found.'}, status=403)
            except ValidationError as e:
                return JsonResponse({'Message': f'Validation error: {str(e)}'}, status=400)
        
        else:
            return JsonResponse({'Message': 'User Details not found.'}, status=403)



class DashboardView(View):
    def get(self, request):
        img = Image.objects.filter(public=True)
        return render(request, "myapp/dashboard.html", {"img": img})


class SuperDashboardView(View):
    def get(self, request):
        img = Image.objects.all()
        return render(request, "myapp/dashboard.html", {"img": img})



class UpdateUserDeatilView(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if user:
            if 'name' in request.POST:
                user.name = request.POST['name']
            user.save()
            return Response({'Message': 'User details updated successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'Message': 'No user found.'}, status=status.HTTP_400_BAD_REQUEST)
        

from datetime import datetime, timedelta
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect


class RegenerateImageView(APIView):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        # Retrieve image ID from the request data
        # Get user ID from the request (assuming you have authentication implemented)
        user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()
        # if user.credit < 1:
        #     msg = 'Insufficient credit to perform this action.'
        #     return Response({"Message": msg}, status=status.HTTP_402_PAYMENT_REQUIRED)
        if user_id:
            if not 'image_id' in request.data or not request.data.get('image_id'):
                return JsonResponse({'Message': 'Image not found'}, status=404)
            image_id = request.data.get('image_id')

            print(image_id)
            try: 
                # Fetch the original image details from the database
                original_image = Image.objects.get(id=image_id, user__id=user_id)
                # Apply your regeneration logic here
                regenerated_image = self.regenerate_image_logic(original_image)
                # Calculate the regenerative_at datetime based on frequency and frequency_type
                regenerative_at_ = calculate_regeneration_time(original_image.frequency,original_image.frequency_type)
                # Save the regenerated image to S3 and database
                user = CustomUser.objects.filter(id=user_id).first()
                try:
                    self.save_to_s3(regenerated_image, original_image, user, regenerative_at_)
                    user.credit= user.credit - 1
                    user.save()

                    credit_balance_left = user.credit

# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
                    # Record the credit deduction history
                    deduction_description = f"Deducted 1 credit for regenerating image '{original_image.image_name}'"
                    CreditHistory.objects.create(
                        user=user,
                        total_credits_deducted=1,
                        type_of_transaction="Credit Deduction",
                        date_time=datetime.now(pytz.utc),
                        payment_id="",  # You can leave this blank for credit deductions
                        description=deduction_description,
                        credit_balance_left=credit_balance_left
                    )
# --------------------------CODE TO SAVE CREDIT DEDUCTION HISTORY------------------------------------------------------------------
                except Exception as e:
                    return JsonResponse({'Message': f'{str(e)}'}, status=400)
                return JsonResponse({'Message': 'Regenerated image saved successfully'}, status=200)
            except:
                return JsonResponse({'Message': 'Image not exist'}, status=400)
        else:
            return JsonResponse({'Message': 'User not authenticated'}, status=401)


    def preprocess_image(self, image_path, target_size=(1024, 1024)):
        from PIL import Image
        import io
        print("Hi, I am here")
        # # Open the image file
        # with Image.open(image_path) as img:
        #     # Convert image to RGBA mode
        #     img = img.convert("RGBA")
        #     # Resize the image
        #     resized_img = img.resize(target_size)
        #     # Create a BytesIO object to store the image data
        #     img_byte_array = io.BytesIO()
        #     # Save the image to the BytesIO object in PNG format
        #     resized_img.save(img_byte_array, format="PNG")
        #     # Get the bytes from the BytesIO object
        #     processed_image = img_byte_array.getvalue()

        print("Downloading image from:", image_path)
        # Download the image from the URL
        response = requests.get(image_path)
        if response.status_code != 200:
            raise Exception("Failed to download image")

        # Open the downloaded image
        with Image.open(io.BytesIO(response.content)) as img:
            # Convert image to RGBA mode
            img = img.convert("RGBA")
            # Resize the image
            resized_img = img.resize(target_size)
            # Create a BytesIO object to store the image data
            img_byte_array = io.BytesIO()
            # Save the image to the BytesIO object in PNG format
            resized_img.save(img_byte_array, format="PNG")
            # Get the bytes from the BytesIO object
            processed_image = img_byte_array.getvalue()
        return processed_image




    def generate_image(self, image_path):
        # Preprocess the image
        openai_api_key=openai_account.objects.first()
        api_key=openai_api_key.key
        preprocessed_image = self.preprocess_image(image_path)
        client = OpenAI(api_key=api_key)

        # Generate image based on prompt and preprocessed image
        # response = client.images.edit(
        #     model="dall-e-2",
        #     image=preprocessed_image,
        #     prompt=prompt,
        #     n=1,
        #     size="1024x1024"
        # )

        response = client.images.create_variation(
        image=preprocessed_image,
        n=2,
        size="1024x1024"
        )

        # Extract URL of the generated image from the API response
        generated_image_url = response.data[0].url

        return generated_image_url
    

    def regenerate_image_logic(self, original_image):
        image_path=str(original_image.photo)
        regenerated_image_url = self.generate_image(image_path)
        return  regenerated_image_url


    def save_to_s3(self, image_url, original_image, user, regenerative_at_):
        s3 = boto3.client('s3', aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        original_image_id = original_image.id
        original_image_name = original_image.image_name

        # Download the image data from the URL
        image_data = requests.get(image_url).content

        # Upload the binary data to your S3 bucket
        file_path = f'{original_image_name}.png'
        s3.put_object(Body=image_data, 
                    Bucket=settings.AWS_STORAGE_BUCKET_NAME2, 
                    Key=file_path,
                    ContentType='image/png',  
                    ContentDisposition='inline')

        s3_base_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME2}.s3.amazonaws.com/"
        regenerated_image_url = s3_base_url + file_path

        regen_image=RegeneratedImage.objects.filter(original_image_id=original_image_id).first()

        regen_image.nextregeneration_at=regenerative_at_
        regen_image.regenerated_at=datetime.now(pytz.utc)
        regen_image.save()


        # regenerated_image = RegeneratedImage.objects.create(
        #     user=user,
        #     original_image_name=original_image_name,
        #     original_image_id=original_image.id,
        #     regenerated_image=regenerated_image_url,
        #     regenerated_at=datetime.now(pytz.utc),
        #     public=original_image.public,
        #     nextregeneration_at=regenerative_at_,
        #     original_image_key_id=original_image  # Set the foreign key
        # )

        original_image.regenerated_at = datetime.now(pytz.utc)
        original_image.nextregeneration_at = regenerative_at_
        original_image.save()



        # Optionally, perform any additional processing or logging



class DepositeMoneyAPI(APIView):
    """ 
    Get a user profile data with email and password
    """
    def post(self, request, format=None):
        transection_id = 0
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user :
            msg = 'could not diposite in the user account'
            return Response({ "transaction_id":transection_id, "Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not 'money' in request.data and not request.data['money']:
            msg = 'could not found the money'
            return Response({ "transaction_id":transection_id, "Message": msg}, status=status.HTTP_400_BAD_REQUEST)
        transection_id = random.randint(100000000,99999999999)
        DepositeMoney.objects.create(user=user,Amount= request.data['money'],TransactionId = str(transection_id), method = "CREDIT_CARD", status = "COMPLETE" )
        
        msg = 'successfully transaction completed !'
        return Response({ "transaction_id":transection_id, "Message": msg}, status=status.HTTP_200_OK)
    
class GetDipositeList(APIView):
    """ 
    Get-all-user if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        if 'TransactionId' in request.data:
            all_diposite = DepositeMoney.objects.filter(TransactionId=request.data['TransactionId'])
            if not all_diposite :
                return Response({'Message' : 'counld not got the diposite', 'TransactionId' : request.data['TransactionId']}, status=status.HTTP_204_NO_CONTENT)
                
        else :
            all_diposite = DepositeMoney.objects.filter()
            
        diposite_list = [ 
                     {
                         dp.TransactionId : {
                             "amount" : dp.Amount,
                             "method" : dp.method,
                             "status" : dp.status,
                             "user" : dp.user.email,
                         } 
                         } 
                     for dp in all_diposite ]
        
        
        # diposite_list = [ {c_user.id : { 'email' : c_user.email, 'credit' : c_user.credit, 'fname' : c_user.first_name, "Diposited_balance" : sum([dp_obj.Amount for dp_obj in DepositeMoney.objects.filter(user=c_user)]) if  sum([dp_obj.Amount for dp_obj in DepositeMoney.objects.filter(user=c_user)]) else 0, "search_history" : [ {"hashtag" : search.hashtag, "platform" : search.platform } for search in SearchedHistory.objects.filter(user=c_user)] }} for c_user in all_diposite ]
        if diposite_list :
            return Response({'Message' : 'successfully got the user list','userlist' : diposite_list}, status=status.HTTP_200_OK)
        return Response({'Message' : 'counld not got the user list', 'userlist' : diposite_list}, status=status.HTTP_204_NO_CONTENT)




#---------------------------------------------------Credit Pricing VIEWS------------------------------------------------------

from .models import CreditPricing
from .serializers import CreditPricingSerializer

# -------------------------------------------------View Credit Balance API ----------------------------------------------------
class GetCreditBalance(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        # user_id = get_user_id_from_token(request)
        # user, _ = IsSuperUser(user_id)
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            credit_balance = user.credit
            return Response({'Message': 'Credit balance fetched successfully', "Credits":credit_balance})
        except Exception as e:
            return Response({'Message':str(e)}, status=status.HTTP_400_BAD_REQUEST)
# -------------------------------------------------View Credit Balance API ----------------------------------------------------

class CreditPricingAPIView(APIView):
    # renderer_classes = [UserRenderer]
    # permission_classes = [IsAuthenticated]

    def get(self,request):
        # user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()
        # user_id = get_user_id_from_token(request)
        # user, _ = IsSuperUser(user_id)
        # if not user:
        #     return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        credit_pricing = CreditPricing.objects.first()
        if not credit_pricing:
            return Response({"Message": "Credit pricing not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreditPricingSerializer(credit_pricing)
        #return Response(serializer.data )
        data = serializer.data
        data['Currency'] = 'USD'  # Add Currency to the response data
        # return Response(data)
        return Response({'Message': 'Credit pricing fetched successfully',"Credit Pricing":data}, status=status.HTTP_200_OK)

class UpdateCreditPricingAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'Could not find the Admin user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            credit_pricing = CreditPricing.objects.first()

            # Check if 'price' is provided in request data
            price = request.data.get('price')
            if price is not None:
                credit_pricing.price = price
                credit_pricing.save()
                return Response({'Message': 'Credit pricing updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'No pricing update available'}, status=status.HTTP_400_BAD_REQUEST)
            # if not credit_pricing:
            #     #credit_pricing = CreditPricing.objects.create()
            #     return Response({"Message": "Credit pricing not found"}, status=status.HTTP_404_NOT_FOUND)
            # if 'price' or request.POST.get('price'):
            #     credit_pricing.price = request.data.get('price', credit_pricing.price)
            #     credit_pricing.save()
            #     return Response({'Message': 'Credit pricing updated successfully'})
            # else:
            #     return Response({'Message': 'No pricing update available'})
        
        except Exception as e:
            return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

#---------------------------------------------------Credit Pricing VIEWS------------------------------------------------------
        
#---------------------------------------------------Payment VIEWS------------------------------------------------------
from .models import PaymentRecord, CreditHistory
from .serializers import PaymentRecordSerializer, CreditHistorySerializer

# class RecordPaymentAPIView(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     def post(self, request, format=None):
#         serializer = PaymentRecordSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GetPaymentHistory(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        payments = PaymentRecord.objects.filter(user=user).order_by('-date_time')
        if payments:
            serializer = PaymentRecordSerializer(payments, many=True)
            # return Response(serializer.data)
            return Response({"Message":"Payment History fetched Succesfully","Payment_History":serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({"Message":"No Payment History Found","Payment_History":None}, status=status.HTTP_400_BAD_REQUEST)
            
# class GetCreditHistoryAPIView(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     def get(self, request, format=None):
#         credit_history = CreditHistory.objects.all()
#         serializer = CreditHistorySerializer(credit_history, many=True)
#         return Response(serializer.data)
    
class GetCreditHistoryAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        # user_id = get_user_id_from_token(request)
        # user, _ = IsSuperUser(user_id)
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        try:       
            credit_history = CreditHistory.objects.filter(user=user).order_by('-date_time')
            serializer = CreditHistorySerializer(credit_history, many=True)
            return Response({'Message': 'Credit History fetched successfully', "Credits":serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'Message': f'Credit History fetched Unsuccessful, {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # try:
        #     credit_balance = user.credit
        #     return Response({'Message': 'Credit balance fetched successfully', "Credits":credit_balance})
        # except Exception as e:
        #     return Response({'Message':str(e)})

#---------------------------------------------------Payment VIEWS------------------------------------------------------




#--------------------------------------------------stripe-------------------------------------------------------------

from django.views.generic import TemplateView
from django.utils import timezone
import stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


#--------------------------------------------------stripe-------------------------------------------------------------


class CheckoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # user = request.user
        if user.is_authenticated:
            if user.stripe_customer_id:
                try:
                    customer = stripe.Customer.retrieve(user.stripe_customer_id)
                    subscriptions = stripe.Subscription.list(customer=user.stripe_customer_id, status='active')
                    if subscriptions.data:
                        # User is subscribed, redirect to subscription management page
                        return redirect('subscription_management')
                    else:
                        # User is an existing customer but not subscribed, send to checkout page
                        return render(request, 'checkout.html', {
                            'stripe_public_key': settings.STRIPE_PUBLIC_KEY,
                            'memberships': Membership.objects.all()
                        })

                        # if customer.invoice_settings.default_payment_method:
                        #     # Customer has a default payment method, render checkout page
                        #     return render(request, 'checkout.html', {
                        #         'stripe_public_key': settings.STRIPE_PUBLIC_KEY,
                        #         'memberships': Membership.objects.all()
                        #     })
                        # else:
                        #     # Customer does not have a default payment method, redirect to add payment method page
                        #     return Response({"url":f'https://buy.stripe.com/28og1h5834Lb79S5kk?session_id={user.stripe_customer_id}'})  # You need to define this URL
                            

                except stripe.error.InvalidRequestError as e:
                    # Stripe customer retrieval failed
                    # return redirect('create_stripe_customer')
                    return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # User is not an existing customer, proceed to create new customer account
                return redirect('create_stripe_customer')
        else:
            # User is not authenticated, redirect to login page
            return redirect('login')
        
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        total_credits = request.data.get('total_credits', 0)
        membership_id = request.data.get('membership_id')

        print("The MEMBERSHIP ID IS GIVEN AS :",membership_id)
        print("The credits are GIVEN AS :",total_credits)

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user

        if membership_id:
            membership = Membership.objects.get(id=membership_id)
            total_amount = membership.price
            item_name = membership.name
            total_credits = membership.credits

            try:
                if not user.stripe_customer_id:
                    # Create a new Stripe customer if not exists
                    customer = stripe.Customer.create(email=user.email, name=user.get_full_name())
                    user.stripe_customer_id = customer.id
                    user.save()
                else:
                    customer = stripe.Customer.retrieve(user.stripe_customer_id)

                # # Create a subscription
                # subscription = stripe.Subscription.create(
                #     customer=user.stripe_customer_id,
                #     items=[{'price': membership.stripe_price_id}],
                #     expand=['latest_invoice.payment_intent']
                # )

                # PaymentRecord.objects.create(
                #     total_amount=total_amount,
                #     total_credits=total_credits,
                #     payment_id="Temp",
                #     payment_mode='Stripe',
                #     user=user,
                #     payment_status='Pending',
                #     membership=membership,
                #     date_time=timezone.now() 
                # )

                # return Response({'subscriptionId': "TEMP"})

            except stripe.error.CardError as e:
                return Response({'error': str(e)}, status=400)



        else:
            credit_price = CreditPricing.objects.first().price
            total_amount = total_credits * credit_price
            # total_amount = request.POST.get('total_amount')
            item_name = f'{total_credits} Credits'

        if membership_id:

            membership = Membership.objects.get(id=membership_id)
            price_id = membership.stripe_price_id
            customer_id = user.stripe_customer_id  # Replace 'your_customer_id' with the actual customer ID

            #stripe.api_key = "sk_test_51OmR7LFgeSLbzlIV4PWYM8azw8RoCk86r1YrmaQYGJsueGVkvY8jHcQsxZgNiOvrAzLJREhwm6lJm7R8fLuwfwte00gRgjL3Nb"

            session = stripe.checkout.Session.create(
            # success_url='https://example.com/success.html?session_id={CHECKOUT_SESSION_ID}',
            # cancel_url='https://example.com/canceled.html',
            success_url=settings.FRONTEND_DOMAIN + '/payment/success/',
            cancel_url=settings.FRONTEND_DOMAIN + '/payment/failed/',
            mode='subscription',
            line_items=[{
                'price': price_id,
                'quantity': 1
            }],
            customer=customer_id
            )

            PaymentRecord.objects.create(
                    total_amount=total_amount,
                    total_credits=total_credits,
                    payment_id=session['id'],
                    payment_mode='Stripe',
                    user=user,
                    payment_status='Pending',
                    membership=membership if membership_id else None,
                    date_time=timezone.now() 
                )

            return Response({"Session ID":session})



        else:
            try:
                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': item_name,
                            },
                            'unit_amount': int(float(total_amount) * 100),
                        },
                        'quantity': 1,
                    }],
                    customer=user.stripe_customer_id,
                    mode='payment',
                    success_url=settings.FRONTEND_DOMAIN + '/payment/success/',
                    cancel_url=settings.FRONTEND_DOMAIN + '/payment/failed/',
                    expires_at=int((timezone.now() + timedelta(minutes=30)).timestamp()),  # Expires in 10 minutes
                    metadata={
                        'user_id': user.id,
                        'membership_id': membership_id if membership_id else '',
                        'total_credits': total_credits,
                    }
                )

                PaymentRecord.objects.create(
                    total_amount=total_amount,
                    total_credits=total_credits,
                    payment_id=checkout_session['id'],
                    payment_mode='Stripe',
                    user=user,
                    payment_status='Pending',
                    membership=membership if membership_id else None,
                    date_time=timezone.now() 
                )

                return Response({'sessionId': checkout_session['id']})

            except stripe.error.CardError as e:
                return Response({'error': str(e)}, status=400)
        # elif membership_id:

        #     membership = Membership.objects.get(id=membership_id)
        #     price_id = membership.stripe_price_id
        #     customer_id = user.stripe_customer_id  # Replace 'your_customer_id' with the actual customer ID

        #     #stripe.api_key = "sk_test_51OmR7LFgeSLbzlIV4PWYM8azw8RoCk86r1YrmaQYGJsueGVkvY8jHcQsxZgNiOvrAzLJREhwm6lJm7R8fLuwfwte00gRgjL3Nb"

        #     session = stripe.checkout.Session.create(
        #     # success_url='https://example.com/success.html?session_id={CHECKOUT_SESSION_ID}',
        #     # cancel_url='https://example.com/canceled.html',
        #     success_url=settings.FRONTEND_DOMAIN + '/payment/success/',
        #     cancel_url=settings.FRONTEND_DOMAIN + '/payment/failed/',
        #     mode='subscription',
        #     line_items=[{
        #         'price': price_id,
        #         'quantity': 1
        #     }],
        #     customer=customer_id
        #     )

        #     # PaymentRecord.objects.create(
        #     #         total_amount=total_amount,
        #     #         total_credits=total_credits,
        #     #         payment_id=checkout_session['id'],
        #     #         payment_mode='Stripe',
        #     #         user=user,
        #     #         payment_status='Pending',
        #     #         membership=membership if membership_id else None,
        #     #         date_time=timezone.now() 
        #     #     )

        #     return Response({"Session ID":session})


class PaymentSuccessView(TemplateView):
    template_name = 'payment_success.html'

class PaymentFailedView(TemplateView):
    template_name = 'payment_failed.html'

@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(View):
    def post(self, request):
        payload = request.body
        sig_header = request.headers.get('Stripe-Signature')
        # print("sig_header :",sig_header)
        # print("The Paylaod is: ",payload)
        # print("The settings.STRIPE_WEBHOOK_SECRET: ",settings.STRIPE_WEBHOOK_SECRET)

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except (ValueError, stripe.error.SignatureVerificationError) as e:
            return HttpResponse(status=400)
        print("The event details are as follows: ",event)

        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            # print("THE DETAILS OF THE SESSSION IS AS FOLLOWS : ",session)
            if session['subscription']:
                payment_record = PaymentRecord.objects.get(payment_id=session['id'])
                subscription_id = session['subscription']
                payment_record.payment_id = subscription_id
                print("The session is as follows",session)


                # payment_record = PaymentRecord.objects.get(payment_id=subscription_id)
            else:
                payment_record = PaymentRecord.objects.get(payment_id=session['id'])
                payment_intent_id = session['payment_intent']
                print("THE DETAILS OF THE SESSSION IS AS FOLLOWS : ",session)
                print("The Paymnet intent id is :",payment_intent_id)
                payment_record.payment_id = payment_intent_id


                print("The payment_intent_id id is a s follows",payment_intent_id)

                # payment_record = PaymentRecord.objects.get(payment_id=payment_intent_id)
            # subscription_id = session['subscription']   # BUT HOW WILL IT SEARCH FOR WHICH EVENT WE HAVE TO SET IT?
            # print(session)
            # payment_record = PaymentRecord.objects.get(payment_id=session['id'])
            payment_record.payment_status = 'Paid'
            payment_record.payment_description = "Payment Successful"
            payment_record.save()

            user = payment_record.user
            if not user.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=user.get_full_name(),
                )
                user.stripe_customer_id = customer.id
                user.save()
                # return redirect('create_stripe_customer')

            if payment_record.membership:
                user = payment_record.user
                user.membership = payment_record.membership
                user.membership_expiry = timezone.now() + timedelta(days=payment_record.membership.duration_days)
                user.credit = user.credit + payment_record.total_credits
                user.is_subscribed=True
                user.save()

                addition_description =f"Added {payment_record.total_credits} credit to the user {user.email} via stripe"

                # HERE CREDITHISTORY RECORD SHOULD ALSO BE CREATED
                CreditHistory.objects.create(
                user=user,
                total_credits_deducted=payment_record.total_credits,
                type_of_transaction="Credit Addition",
                date_time=datetime.now(pytz.utc),
                payment_id=payment_record.payment_id,  # You can leave this blank for credit deductions
                description=addition_description,
                credit_balance_left=user.credit
                )



            else:
                user = payment_record.user
                # user.membership = payment_record.membership
                # user.membership_expiry = timezone.now() + timedelta(days=payment_record.membership.duration_days)
                user.credit = user.credit + payment_record.total_credits
                user.save()

                addition_description =f"Added {payment_record.total_credits} credit to the user {user.email} via stripe"

                # HERE CREDITHISTORY RECORD SHOULD ALSO BE CREATED
                CreditHistory.objects.create(
                user=user,
                total_credits_deducted=payment_record.total_credits,
                type_of_transaction="Credit Addition",
                date_time=datetime.now(pytz.utc),
                payment_id=payment_record.payment_id,  # You can leave this blank for credit deductions
                description=addition_description,
                credit_balance_left=user.credit
                )
        
        elif event['type'] == 'customer.subscription.created':
            session = event['data']['object']
            subscription = event['data']['object']
            subscription_id = subscription['subscription']
            payment_record = PaymentRecord.objects.get(payment_id=session['id'])
            payment_record.payment_status = 'Paid'
            payment_record.payment_description = "Subscription Created Successfully"
            payment_record.payment_id = subscription_id
            payment_record.save()

            user = payment_record.user
            if user:
                user.is_subscribed = True
                
                # Assuming `membership` is a field that stores the plan ID or some subscription details
                user.membership = subscription['plan']['id']
                
                # If you want to set an expiry date, you might need to calculate it based on the current period end
                # For example, setting membership_expiry to the end of the current billing period
                current_period_end = subscription['current_period_end']
                user.membership_expiry = datetime.fromtimestamp(current_period_end)
                
                user.save()



        elif event['type'] == 'checkout.session.expired':
            session = event['data']['object']
            payment_record = PaymentRecord.objects.get(payment_id=session['id'])
            payment_record.payment_status = 'Failed'
            payment_record.payment_description = "Session Expired"
            payment_record.save()
            user = payment_record.user
            if not user.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=user.get_full_name(),
                )
                user.stripe_customer_id = customer.id
                user.save()

        elif event['type'] == 'invoice.payment_succeeded':
            invoice = event['data']['object']
            subscription_id = invoice['subscription']
            payment_record = PaymentRecord.objects.get(payment_id=subscription_id)
            payment_record.payment_status = 'Paid'
            payment_record.payment_description = "Subscription Payment Successful"
            payment_record.save()

            user = payment_record.user
            user.membership_expiry = timezone.now() + timedelta(days=payment_record.membership.duration_days)
            user.credit += payment_record.total_credits
            user.save()

            CreditHistory.objects.create(
                user=user,
                total_credits_deducted=payment_record.total_credits,
                type_of_transaction="Credit Addition",
                date_time=timezone.now(),
                payment_id=payment_record.payment_id,
                description=f"Subscription payment credited {payment_record.total_credits} to the user {user.email}",
                credit_balance_left=user.credit
            )

        elif event['type'] == 'invoice.payment_failed':
            invoice = event['data']['object']
            subscription_id = invoice['subscription']
            payment_record = PaymentRecord.objects.get(payment_id=subscription_id)
            payment_record.payment_status = 'Failed'
            payment_record.payment_description = "Subscription Payment Failed"
            payment_record.save()


        elif event['type'] == 'customer.subscription.deleted':
            subscription = event['data']['object']
            
            subscription_id = subscription['subscription']
            payment_record = PaymentRecord.objects.get(payment_id=subscription_id)
            payment_record.payment_status = 'Failed'
            payment_record.payment_description = "Subscription Cancelled Successfully"
            payment_record.save()

            user = payment_record.user
            if user:
                user.is_subscribed = False
                user.membership_expiry = None
                user.membership = None
                user.save()


        elif event['type'] == 'payment_intent.payment_failed':
            payment_intent = event['data']['object']
            error_message = payment_intent.get('last_payment_error', {}).get('message')
            # Handle the payment failure event here, you can log the error message or take appropriate action
            payment_record = PaymentRecord.objects.get(payment_id=session['id'])
            payment_record.payment_status = 'Failed'
            payment_record.payment_description = error_message
            payment_record.save()
            user = payment_record.user
            if not user.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=user.get_full_name(),
                )
                user.stripe_customer_id = customer.id
                user.save()

        elif event['type'] == 'payment_intent.canceled':
            print(" I am inside payment cancelled")
            payment_intent = event['data']['object']
            error_message = payment_intent.get('last_payment_error', {}).get('message')
            # Handle the payment failure event here, you can log the error message or take appropriate action
            payment_record = PaymentRecord.objects.get(payment_id=session['id'])
            payment_record.payment_status = 'Failed'
            payment_record.payment_description = error_message
            payment_record.save()
            user = payment_record.user
            if not user.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=user.get_full_name(),
                )
                user.stripe_customer_id = customer.id
                user.save()


        return HttpResponse(status=200)

@method_decorator(csrf_exempt, name='dispatch')
class CreateStripeCustomerView(View):
    def get(self, request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user
        if user.is_authenticated:
            try:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=user.get_full_name(),
                )
                user.stripe_customer_id = customer.id
                user.save()
                return redirect('checkout')
            except Exception as e:
                return HttpResponse(f"Error creating Stripe customer: {e}", status=400)
        else:
            return redirect('login')

@method_decorator(csrf_exempt, name='dispatch')
class SubscriptionManagementView(View):
    def get(self, request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user
        if user.is_authenticated:
            try:
                subscriptions = stripe.Subscription.list(customer=user.stripe_customer_id)
                return render(request, 'subscription_management.html', {
                    'subscriptions': subscriptions
                })
            except Exception as e:
                return HttpResponse(f"Error retrieving subscriptions: {e}", status=400)
        else:
            return redirect('login')
        

    

class CancelSubscriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_subscribed or not user.membership:
            return Response({"Message": "User is not subscribed to any membership"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            subscriptions = stripe.Subscription.list(customer=user.stripe_customer_id, status='active')
            if not subscriptions.data:
                return Response({"Message": "No active subscription found"}, status=status.HTTP_400_BAD_REQUEST)

            # Cancel the subscription
            subscription_id = subscriptions.data[0].id  # Assuming the user has only one active subscription
            stripe.Subscription.delete(subscription_id)

            # Update user model
            user.is_subscribed = False
            user.membership_expiry = None
            user.membership = None
            user.save()
            
            return Response({"Message": "Subscription cancelled successfully"}, status=status.HTTP_200_OK)
        except stripe.error.StripeError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class get_membership(APIView):
    def post(self,request):
        # user_id = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=user_id).first()
        # if not user:
        #     return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        lst=[]
        membership_list = Membership.objects.all()
        # print(settings.YOUR_DOMAIN)
        # print(type(settings.YOUR_DOMAIN))
        if membership_list:
            for membership in membership_list:
                mem={
                    "Membership ID":membership.id,
                    "Membership Name":membership.name,
                    "Membership Price":membership.price,
                    "Membership Credits":membership.credits,
                    "Membership Duration":membership.duration_days,
                    "Membership Feature 1":membership.membership_feature_1,
                    "Membership Feature 2":membership.membership_feature_2,
                    "Membership Feature 3":membership.membership_feature_3,
                    "Membership Feature 4":membership.membership_feature_4,
                    "Membership Feature 5":membership.membership_feature_5,
                }

                lst.append(mem)

            return Response({"Message":"Membership Details fetched Succesfully","Membership_details":lst}, status=status.HTTP_200_OK)
        else:
            return Response({"Message":"No Membership Details Found","Membership_details":None}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from dateutil.relativedelta import relativedelta   
from datetime import datetime

class AdminUpdateMembership(APIView):
    """ 
    Update-Membership-details if token is of super user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        if 'membership_id' not in request.data or not request.data.get('membership_id'):
            msg = 'could not found the membership_id'
            return Response({'Message' : msg}, status=status.HTTP_400_BAD_REQUEST)
        
        if not any(key in request.data for key in ['price', 'name', 'duration_days', 'credits', 'stripe_price_id', 'Membership Feature 1', 'Membership Feature 2', 'Membership Feature 3', 'Membership Feature 4', 'Membership Feature 5']):
            msg = 'No details given to update in Membership.'
            return Response({'Message': msg}, status=status.HTTP_400_BAD_REQUEST)
            
        membership = Membership.objects.filter(id=request.data.get('membership_id')).first()
        if not membership :
            return Response({'Message' : 'Could not got the Membership Details'}, status=status.HTTP_204_NO_CONTENT)

        try:

            if 'price' in request.data:
                membership.price = request.data['price']
            if 'name' in request.data:
                membership.name = request.data['name']
            if 'duration_days' in request.data:
                membership.duration_days = request.data['duration_days']
            if 'credits' in request.data:
                membership.credits = request.data['credits']

            membership.save()
            
            msg = 'Successfully Modified the Membership details'
            status_code = status.HTTP_200_OK
            
        except Exception as e:
            msg = f'Membership details Update Failed: {str(e)}'
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return Response({'Message' : msg}, status=status_code)
    
class get_credit_detail(APIView):
    """ 
    Get-Credit-details if token is of user
    """
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        user_id=get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"})

        if not "transaction_type" in request.data or not request.data.get("transaction_type"):
            return Response({"Message":"Please specify the Transaction type eg: Credit Addition or Credit Deduction"})
        
        if not "date_filter" in request.data or not request.data.get("date_filter"):
            return Response({"Message":"Please specify the date_filter eg: day, week, month, year or custom"})

        # # type_of_transaction="Credit Addition",Credit Deduction
        date_filter = request.data.get("date_filter")

        if date_filter:
            if date_filter == "custom":
                if not "start_date" in request.data or not request.data.get("start_date"):
                    return Response({"Message":"Please specify the start_date eg: 20-04-2020"})
                if not "end_date" in request.data or not request.data.get("end_date"):
                    return Response({"Message":"Please specify the end_date eg: 20-10-2020"})
                # start_date=request.data.get("start_date").strftime("%d/%m/%Y %H:%M:%S")
                # end_date=request.data.get("end_date").strftime("%d/%m/%Y %H:%M:%S")

                try:
                    start_date = datetime.strptime(request.data.get("start_date"), "%d-%m-%Y")
                    end_date = datetime.strptime(request.data.get("end_date"), "%d-%m-%Y")
                except ValueError:
                    return Response({"Message":"Date format should be DD-MM-YYYY"})
            else:
                if not "frequency" in request.data or not request.data.get("frequency"):
                    return Response({"Message":"Please specify the frequency eg: 1,2 ..."})
                frequency = request.data.get("frequency")




        #periods = request.data.get("periods")
        now=datetime.now(pytz.utc)

        if date_filter == 'month' or date_filter == 'week' or date_filter == 'year' or date_filter == 'day':
            if date_filter == 'week':
                end_date = now
                start_date = now - timedelta(weeks=frequency)
            elif date_filter == 'month':
                end_date = now
                start_date = now - relativedelta(months=frequency)
            elif date_filter == 'year':
                end_date = now
                start_date = now - relativedelta(years=frequency)
            elif date_filter == 'day':
                end_date = now
                start_date = now - timedelta(days=frequency)
        else:
            start_date=start_date
            end_date=end_date

            # "total_deposit_amount" : DepositeMoney.objects.filter(status="COMPLETE",created__gte=start_date,  created__lte=end_date).aggregate(total_amount=Sum('Amount'))['total_amount'],


        try:
            transaction_type = request.data.get("transaction_type")

            credit_detail = CreditHistory.objects.filter(type_of_transaction=transaction_type, user=user, date_time__gte=start_date,  date_time__lte=end_date).order_by('-date_time')
            # credit_detail = CreditHistory.objects.filter(type_of_transaction=transaction_type, user=user)


            lst=[]
            if credit_detail:
                for credits in credit_detail:
                    mem={
                        "CreditHistory ID":credits.id,
                        "CreditHistory Credits":credits.total_credits_deducted,
                        "CreditHistory Transaction Type":credits.type_of_transaction,
                        "CreditHistory Payment ID":credits.payment_id,
                        "CreditHistory Date Time":credits.date_time.strftime("%d/%m/%Y %H:%M:%S"),                
                    }

                    lst.append(mem)



            msg = f'Succesfully get the Credit details'
            status_code = status.HTTP_200_OK
            return Response({'Message' : msg, "Credit_details": lst}, status=status_code)


        except Exception as e:
            msg = f'Failed to get the Credit details: {str(e)}'
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response({'Message' : msg}, status=status_code)



class UserPaymentLatest(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        payments = PaymentRecord.objects.filter(user_id=user_id).order_by('-date_time').first()
        if payments:
            stripe_id = user.stripe_customer_id
            subscription_status = user.is_subscribed
            membership_expiry = user.membership_expiry
            membership_name = user.membership.name


            lst = {
                "payment_id": payments.id,
                "total_amount": str(payments.total_amount),
                "total_credits": payments.total_credits,
                "date_time": str(payments.date_time),
                "payment_status": payments.payment_status,
                "payment_mode": payments.payment_mode,
                "payment_description": payments.payment_description,
                "user": user.id,
                "membership": payments.membership.id,
                "stripe_customer_id":stripe_id,
                "subscription_status":subscription_status,
                "membership_expiry":str(membership_expiry),
                "membership_name":membership_name,

            }


            # serializer = PaymentRecordSerializer(payments, many=False)
            # return Response(serializer.data)
            return Response({"Message":"Payment Details fetched Succesfully","Payment_details":lst}, status=status.HTTP_200_OK)
        else:
            return Response({"Message":"No Payment Details Found","Payment_details":None}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# class UpgradeSubscriptionView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()
#         if not user:
#             return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

#         new_membership_id = request.data.get('new_membership_id')
#         if not new_membership_id:
#             return Response({"Message": "New membership ID is required"}, status=status.HTTP_400_BAD_REQUEST)

#         new_membership = Membership.objects.get(id=new_membership_id)
#         current_subscription_id = stripe.Subscription.list(customer=user.stripe_customer_id, status='active').data[0].id

#         try:
#             updated_subscription = stripe.Subscription.modify(
#                 current_subscription_id,
#                 cancel_at_period_end=False,
#                 proration_behavior='create_prorations',
#                 items=[{
#                     'id': stripe.Subscription.retrieve(current_subscription_id).items.data[0].id,
#                     'price': new_membership.stripe_price_id,
#                 }]
#             )
#             user.membership = new_membership
#             user.save()

#             return Response({'subscriptionId': updated_subscription.id})

#         except stripe.error.StripeError as e:
#             return Response({'error': str(e)}, status=400)

# class DowngradeSubscriptionView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()
#         if not user:
#             return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

#         new_membership_id = request.data.get('new_membership_id')
#         if not new_membership_id:
#             return Response({"Message": "New membership ID is required"}, status=status.HTTP_400_BAD_REQUEST)

#         new_membership = Membership.objects.get(id=new_membership_id)
#         current_subscription_id = stripe.Subscription.list(customer=user.stripe_customer_id, status='active').data[0].id

#         try:
#             updated_subscription = stripe.Subscription.modify(
#                 current_subscription_id,
#                 cancel_at_period_end=False,
#                 proration_behavior='create_prorations',
#                 items=[{
#                     'id': stripe.Subscription.retrieve(current_subscription_id).items.data[0].id,
#                     'price': new_membership.stripe_price_id,
#                 }]
#             )
#             user.membership = new_membership
#             user.save()

#             return Response({'subscriptionId': updated_subscription.id})

#         except stripe.error.StripeError as e:
#             return Response({'error': str(e)}, status=400)

# @csrf_exempt
# def update_subscription(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()
#         if not user:
#             return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

#         new_membership_id = data['new_membership_id']
#         if not new_membership_id:
#             return Response({"Message": "New membership ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        
#         # data = json.loads(request.body)
#         subscription_id = user.stripe_customer_id
#         # new_membership_id = request.data.get('new_membership_id')

#         mem = Membership.objects.get(id=new_membership_id)
#         new_price_id = mem.stripe_price_id

#         try:
#             # Retrieve the subscription
#             # subscription = stripe.Subscription.retrieve(subscription_id)

#             # Retrieve all subscriptions for the customer.
#             subscriptions = stripe.Subscription.list(customer=user.stripe_customer_id)
#             print("The susbcription are as follows: ",subscriptions)
#             # Extract and print subscription IDs.
#             subscription_ids = [subscription.id for subscription in subscriptions.auto_paging_iter()]

#             print(subscription_ids)

#             subscription_id = subscription_ids[0]

#             subscription = stripe.Subscription.retrieve(subscription_id)


#             # return JsonResponse({"ID":f"The is is as {subscription_ids[0]}"})

#             # Update the subscription with proration
#             updated_subscription = stripe.Subscription.modify(
#                 subscription_id,
#                 items=[{
#                     'id': subscription['items']['data'][0].id,
#                     'price': new_price_id,
#                 }],
#                 proration_behavior='create_prorations',
#             )

#             # Retrieve the upcoming invoice to see the proration adjustment
#             upcoming_invoice = stripe.Invoice.upcoming(
#                 subscription=subscription_id,
#             )

#             return JsonResponse({
#                 'subscription': updated_subscription,
#                 'upcoming_invoice': upcoming_invoice,
#             })
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

#     return JsonResponse({'error': 'Invalid request method'}, status=405)



@method_decorator(csrf_exempt, name='dispatch')
class UpdateSubscriptionView(APIView):

    def post(self, request, *args, **kwargs):
        try:
            # data = json.loads(request.body)
            user_id = get_user_id_from_token(request)
            user = CustomUser.objects.filter(id=user_id).first()
            if not user:
                return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)

            new_membership_id = request.data.get('new_membership_id')
            if not new_membership_id:
                return Response({"Message": "New membership ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            mem = Membership.objects.get(id=new_membership_id)
            new_price_id = mem.stripe_price_id

            subscriptions = stripe.Subscription.list(customer=user.stripe_customer_id)
            subscription_ids = [subscription.id for subscription in subscriptions.auto_paging_iter()]

            if not subscription_ids:
                return Response({"Message": "No subscriptions found for this customer"}, status=status.HTTP_404_NOT_FOUND)

            subscription_id = subscription_ids[0]
            subscription = stripe.Subscription.retrieve(subscription_id)

            updated_subscription = stripe.Subscription.modify(
                subscription_id,
                items=[{
                    'id': subscription['items']['data'][0].id,
                    'price': new_price_id,
                }],
                proration_behavior='create_prorations',
            )

            upcoming_invoice = stripe.Invoice.upcoming(
                subscription=subscription_id,
            )

            new_mems = Membership.objects.get(stripe_price_id = new_price_id)
            print(new_mems.id)
            print(new_mems.name)

            user.membership = new_mems
            # user.membership.name = new_mems.name
            if not user.membership_expiry:
                user.membership_expiry = timezone.now() + timedelta(days = new_mems.duration_days)
            user.is_subscribed =True
            user.save()
            # return JsonResponse({
            #     'subscription': updated_subscription,
            #     'upcoming_invoice': upcoming_invoice,
            # })
        
            return JsonResponse({
                'Message': "Subscription Updated Sucessfully"
            })
        except Exception as e:
            return JsonResponse({'Message': f"Error Occured : {str(e)}"}, status=400)




@method_decorator(csrf_exempt, name='dispatch')
class ChangeCardDetailView(APIView):
    def post(self, request, *args, **kwargs):
        
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        # data = json.loads(request.body)
        customer_id = user.stripe_customer_id
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=settings.FRONTEND_DOMAIN + '/dashboard/',
            )
            return JsonResponse({'Message': "Proceed with the url to change payment detail",'url': session.url})
        except Exception as e:
            return JsonResponse({'Message': f"Error Occured : {str(e)}"}, status=400)
        # return JsonResponse({'error': 'Invalid request method'}, status=405)