from django.shortcuts import render, redirect
from .forms import ImageForm
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
from django.http import JsonResponse
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
        'refresh': str(refresh),
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

            return Response({"email": 'Email verification code has been set', 'Message': 'Verify your account'},
                            status=status.HTTP_201_CREATED)






#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
    
class UserEmailVerificationView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        # Check if required fields are provided
        if not email or not verification_code:
            return Response({'Message': 'Please provide the following details', 'details': {'email': 'Email', 'verification_code': 'Verification code'}}, status=status.HTTP_400_BAD_REQUEST)

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
                return Response({'token':token,'Message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'Verification code is incorrect. Resent verification code.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            # If email is not in records, prompt user to register first
            return Response({'Message': 'Email not in records. Please register first.'}, status=status.HTTP_400_BAD_REQUEST)

#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
 
#---------------------------------------------------------Resend OTP API by ADIL----------------------------------------------------------------

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'Message':  {"email": 'Please provide an email address.'}}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({'Message': {'non_field_errors': ['Email not in record. Register First!']}}, status=status.HTTP_404_NOT_FOUND)

        if user.check_password(password)  :
            token = get_tokens_for_user(user)
            if user.is_user_verified:
                return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'verified' : user.is_user_verified, 'Message':'Verify your account First!'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'Message':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

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
        
        jsonn_response = {
            'personal_data' : serializer.data,
            'Total_Image_count' : image_count,
            #'Image_data' : Image_history,
            #'deposit_history' : diposit_history
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response


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
            return Response({'Message': 'Please provide the following details', 'details': {'email': 'Email', 'verification_code': 'Verification code', 'new_password': 'New Password'}}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({'Message': 'Please provide the following details', 'details': {'email': 'Email'}}, status=status.HTTP_400_BAD_REQUEST)
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
                # 'frequency_type' : allOriginalImage.frequency_type,#created.strftime("%d/%m/%Y"),
                # 'frequency' : allOriginalImage.frequency,#json.loads(history.result.replace("'", "\"")),
                'created': allOriginalImage.created.strftime("%d/%m/%Y %H:%M:%S"),
                'regenerated_at': allOriginalImage.regenerated_at.strftime("%d/%m/%Y %H:%M:%S") if allOriginalImage.regenerated_at else None,
                'next_regeneration_at': allOriginalImage.nextregeneration_at.strftime("%d/%m/%Y %H:%M:%S"),
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
        }

    

        # Payment Table
        payment = PaymentRecord.objects.filter(user=user_).first()

        if payment:
            payment_tmp={
                "Payment ID" :payment.id,
                "User Email" :payment.user.email,
                "Payment Amount" :payment.total_amount,
                "Total Credits" :payment.total_credits,
                "Payment date time" :payment.date_time.strftime("%d/%m/%Y %H:%M:%S"),
                "Payment Status" :payment.payment_status,
                "Payment Gateway ID" :payment.payment_id,
                "Payment Mode" :payment.payment_mode,
                }

        else:
            payment_tmp = {}

        # Credit Table
        credit = CreditHistory.objects.filter(user=user_).first()
        if credit:
            credit_tmp={
                "credit ID" :credit.id,
                "User Email" :credit.user.email,
                "Total Credits" :credit.total_credits,
                "Transaction Type" :credit.type_of_transaction,
                "Transaction Date Time" :credit.created.strftime("%d/%m/%Y %H:%M:%S"),
                "Payment ID" :credit.payment_id,
                "Description" :credit.description,
                }

        credit_tmp={}

        # Original Image Table
        img = Image.objects.filter(user=user_).first()
        if img:

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
        else:
            One_Original_Image={}


        # Regenerated Image Table
        regen_img = RegeneratedImage.objects.filter(user=user_).first()

        if regen_img:
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
        else:
            One_Regen_Image={}

        jsonn_response = {
            'user_data' : users_tmp,
            'Original_Image_data' : One_Original_Image,
            'Regenerated_Image_data' : One_Regen_Image,
            'Credit_data' : credit_tmp,
            'Payment_data' : payment_tmp,
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
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        if 'image_id' not in request.data or not request.data.get('image_id'):
                    return JsonResponse({'error': 'Image ID not found'}, status=404) 

        image_id = request.data.get('image_id')
        print("The Image ID is: ",image_id)
        try:
            image = Image.objects.get(id=image_id)
            image_name=image.image_name
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

            return JsonResponse({'Message': 'Image deleted successfully.'})
            # else:
            #     return JsonResponse({'Message': 'Image not found.'}, status=404)
        except Image.DoesNotExist:
            return JsonResponse({'Message': 'Image not found.'}, status=404)
        except ClientError as e:
            return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)

# -----------------------------------------------ADMIN Delete Original Image ---------------------------------------------------------------


# -----------------------------------------------ADMIN API's ---------------------------------------------------------------

#----------------------Code copied from Keywordlit Project--------------------------------------------------------------

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
        form = ImageForm(request.POST, request.FILES)
        if form.is_valid():
            # Set the user before saving the form
            user_id = get_user_id_from_token(request)
            user = CustomUser.objects.filter(id=user_id).first()
            if not user:
                return Response({'Message': 'User Not found.'}, status=status.HTTP_401_UNAUTHORIZED)
            print("the user is: ",user.email)
            # Retrieve the uploaded file from request.FILES
            photo = request.FILES.get('photo')
            if not photo:
                return JsonResponse({'error': 'No file uploaded'}, status=400)
            form.instance.user = user
            print("form.instance.user :",form.instance.user)
            frequency = form.cleaned_data.get('frequency')
            prompt = form.cleaned_data.get('prompt')
            frequency_type = form.cleaned_data.get('frequency_type')
            #photo = form.cleaned_data.get('photo')
            public = form.cleaned_data.get('public')
            
            print("The details are as follows for image upload")
            print("frequency:", frequency) 
            print("prompt:", prompt)
            print("frequency_type:", frequency_type)
            print("photo:", photo)
            print("public:", public)

            print("Secret Key",settings.AWS_SECRET_ACCESS_KEY)
            print("Access Key",settings.AWS_ACCESS_KEY_ID)


            max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
                # Check if the size of the uploaded image is less than or equal to the maximum size limit
            if photo.size > max_size:
                return JsonResponse({'error': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=400)


            # Calculate next regeneration datetime
            next_regeneration_at = calculate_regeneration_time(frequency, frequency_type)
            image_name=generate_random_string(15)
            # Save the image file to S3 with the desired file name
            file_name = f"{image_name}.jpg"  # Assuming the image format is JPG
            file_path = default_storage.save(file_name, photo) # It should be a string so we can split it to our need
            print("The file path is : ",file_path)

            # https://livingimage-original-images.s3.amazonaws.com/vqEugYeFSOwJFGe.jpg
            # # For example, let's say you want to save the S3 URL
            # s3_base_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/"
            # regenerated_image_url = s3_base_url + file_name

            # Get the URL using the storage backend
            original_image_url = default_storage.url(file_name)
            print('The original image url is :',original_image_url)

            edit_url=original_image_url.split('?')[0]
            print('The Edited url is :',edit_url)
            

            # try:
            #     print(original_image_url.split('?')[0])
            # except:
            #     pass


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

            # Regenerate and save to S3
            regen_image_url = self.regenerate_image_logic(image_instance)

            # Calculate the regenerative_at datetime based on frequency and frequency_type
            regenerative_at_ = calculate_regeneration_time(image_instance.frequency,image_instance.frequency_type)

            self.save_to_s3(regen_image_url, image_instance, user, regenerative_at_)

            # Deduct User Credit
            user.credit= user.credit - 1
            user.save()
            #form.save()
            #return redirect('/api/dashboard/')
            return JsonResponse({'Message': 'Image Upload successful.'})
        else:
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
                    return JsonResponse({'error': 'Image not found'}, status=404)
                
                image_id = request.data.get("image_id")
                user = CustomUser.objects.filter(id=user_id).first()
                image = Image.objects.get(id=image_id, user=user)
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

                return JsonResponse({'Message': 'Image deleted successfully.'})
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
                return JsonResponse({'error': 'Image not found'}, status=404)
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

                # Check if a new image file is provided
                new_image_data = request.FILES.get('photo')
                if new_image_data:

                    max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
                    # Check if the size of the uploaded image is less than or equal to the maximum size limit
                    if new_image_data.size > max_size:
                        return JsonResponse({'error': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=400)
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
        if user_id:
            if not 'image_id' in request.data or not request.data.get('image_id'):
                return JsonResponse({'error': 'Image not found'}, status=404)
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
            return Response({ "transection_id":transection_id, "Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not 'money' in request.data and not request.data['money']:
            msg = 'could not found the money'
            return Response({ "transection_id":transection_id, "Message": msg}, status=status.HTTP_400_BAD_REQUEST)
        transection_id = random.randint(100000000,99999999999)
        DepositeMoney.objects.create(user=user,Amount= request.data['money'],TransactionId = str(transection_id), method = "CREDIT_CARD", status = "COMPLETE" )
        
        msg = 'successfully transection completed !'
        return Response({ "transection_id":transection_id, "Message": msg}, status=status.HTTP_200_OK)
    
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

class CreditPricingAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()
        # user_id = get_user_id_from_token(request)
        # user, _ = IsSuperUser(user_id)
        if not user:
            return Response({"Message": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        
        credit_pricing = CreditPricing.objects.first()
        if not credit_pricing:
            return Response({"Message": "Credit pricing not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreditPricingSerializer(credit_pricing)
        #return Response(serializer.data )
        data = serializer.data
        data['Currency'] = 'USD'  # Add Currency to the response data
        return Response(data)

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
                return Response({'Message': 'Credit pricing updated successfully'})
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

class RecordPaymentAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = PaymentRecordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GetPaymentHistoryAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        payments = PaymentRecord.objects.all()
        serializer = PaymentRecordSerializer(payments, many=True)
        return Response(serializer.data)

class GetCreditHistoryAPIView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        credit_history = CreditHistory.objects.all()
        serializer = CreditHistorySerializer(credit_history, many=True)
        return Response(serializer.data)
#---------------------------------------------------Payment VIEWS------------------------------------------------------