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
                'image_data' : history.photo.url,
                'public' : history.public,
                'prompt' : history.prompt,
                'frequency_type' : history.frequency_type,#created.strftime("%d/%m/%Y"),
                'frequency' : history.frequency,#json.loads(history.result.replace("'", "\"")),
                'created': history.created.strftime("%d/%m/%Y"),
                'updated': history.updated.strftime("%d/%m/%Y"),
            }
            Image_history.append(tmp)
            image_count=len(Image_history)
        
        diposit_history = []
        for MoneyHistory in DepositeMoney.objects.filter(user=user):
            tmp = {
                'deposit_id' : MoneyHistory.id,
                'date' : MoneyHistory.created.strftime("%d/%m/%Y"),
                'amount' : MoneyHistory.Amount,
                'transection_id' : MoneyHistory.TransactionId,
                'method' : MoneyHistory.method,
                'status' : MoneyHistory.status
            }
            diposit_history.append(tmp)
        
        jsonn_response = {
            'personal_data' : serializer.data,
            'Total_Image_count' : image_count,
            'Image_data' : Image_history,
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
    



from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


#----------------------Code copied from Keywordlit Project--------------------------------------------------------------

class UploadImageView(View):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]


    # @method_decorator(ensure_csrf_cookie)
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
            if user:
                print("the user is: ",user.email)
                form.instance.user = user
                print("form.instance.user :",form.instance.user)
                frequency = form.cleaned_data.get('frequency')
                prompt = form.cleaned_data.get('prompt')
                frequency_type = form.cleaned_data.get('frequency_type')
                photo = form.cleaned_data.get('photo')
                public = form.cleaned_data.get('public')
                
                print("The details are as follows for image upload")
                print("frequency:", frequency) 
                print("prompt:", prompt)
                print("frequency_type:", frequency_type)
                print("photo:", photo)
                print("public:", public)
                max_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
                    # Check if the size of the uploaded image is less than or equal to the maximum size limit
                if photo.size > max_size:
                    return JsonResponse({'error': f'Uploaded image size exceeds the limit ({settings.MAX_IMAGE_SIZE_MB} MB)'}, status=400)

                History.objects.create(
                    tag='create',
                    user=user,
                    image_data=photo,
                    prompt=prompt,
                    frequency_type=frequency_type,
                    frequency=frequency,
                    public=public
                )

                form.save()
                #return redirect('/api/dashboard/')
                return JsonResponse({'Message': 'Image Upload successful.'})
            else:
                return JsonResponse({'Message': 'User Not Found'})
        else:
            print("Form is invalid")
            print(form.errors)
            return JsonResponse({'Message': 'Image Upload Unsuccessful.'}, status=400)

        #     return 'Message Image Upload successful.'
        # else:
        #     print("Form is invalid")
        #     print(form.errors)
        #     return Response({'Message': 'Image Upload Unsuccessful.'}, status=status.HTTP_400_BAD_REQUEST)#render(request, 'myapp/upload.html', {'form': form})

from django.contrib.auth.decorators import login_required


#@method_decorator(csrf_exempt, name='dispatch')
# class DeleteImageView(View):
#     @csrf_exempt
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)

#     def post(self, request):
#         image_id = request.POST.get('image_id')
#         user_id = get_user_id_from_token(request)
#         if user_id:
#             try:
#                 user = CustomUser.objects.get(id=user_id)
#                 image = Image.objects.get(id=image_id, user=user)

#                 # Delete the image file from the S3 bucket
#                 image.photo.delete(save=False)
                
#                 History.objects.create(
#                     tag='delete',
#                     user=user,
#                     image_data=image.photo,
#                     prompt=image.prompt,
#                     frequency_type=image.frequency_type,
#                     frequency=image.frequency,
#                     public=image.public
#                 )

#                 # Delete the image object from the database
#                 image.delete()

#                 return JsonResponse({'Message': 'Image deleted successfully.'})
#             except Image.DoesNotExist:
#                 return JsonResponse({'Message': 'Image not found.'}, status=404)
#             except CustomUser.DoesNotExist:
#                 return JsonResponse({'Message': 'User not found.'}, status=403)
#         else:
#             return JsonResponse({'Message': 'User Details not found.'}, status=403)

class DeleteImageView(View):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        image_id = request.POST.get('image_id')
        user_id = get_user_id_from_token(request)
        if user_id:
            try:
                user = CustomUser.objects.get(id=user_id)
                image = Image.objects.get(id=image_id, user=user)

                # Delete the image file from the S3 bucket
                s3_key = image.photo.name
                if default_storage.exists(s3_key):
                    default_storage.delete(s3_key)

                    # Create a history record before deleting the image object
                    History.objects.create(
                        tag='delete',
                        user=user,
                        image_data=image.photo,
                        prompt=image.prompt,
                        frequency_type=image.frequency_type,
                        frequency=image.frequency,
                        public=image.public
                    )

                    # Delete the image object from the database
                    image.delete()

                    return JsonResponse({'Message': 'Image deleted successfully.'})
                else:
                    return JsonResponse({'Message': 'Image not found.'}, status=404)
            except Image.DoesNotExist:
                return JsonResponse({'Message': 'Image not found.'}, status=404)
            except CustomUser.DoesNotExist:
                return JsonResponse({'Message': 'User not found.'}, status=403)
            except ClientError as e:
                return JsonResponse({'Message': f'An error occurred: {str(e)}'}, status=500)
        else:
            return JsonResponse({'Message': 'User Details not found.'}, status=403)










#@method_decorator(csrf_exempt, name='dispatch')
class UpdateImageView(View):
    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        image_id = request.POST.get('image_id')
        user_id = get_user_id_from_token(request)
        if user_id:
            try:
                user = CustomUser.objects.get(id=user_id)
                image = Image.objects.get(id=image_id, user=user)

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
                    # Delete the old image file from S3
                    if image.photo:
                        image.photo.delete(save=False)
                    # Continue processing the uploaded image
                    # Save the new image file to the model
                    #image.photo.save(new_image_data, new_image_data, save=True)
                    image.photo.save(new_image_data.name, new_image_data, save=True)
                    
                # Save the updated image object
                History.objects.create(
                    tag='update',
                    user=user,
                    image_data=image.photo,
                    prompt=image.prompt,
                    frequency_type=image.frequency_type,
                    frequency=image.frequency,
                    public=image.public)
                image.save()

                return JsonResponse({'Message': 'Image details updated successfully.'})
            except Image.DoesNotExist:
                return JsonResponse({'Message': 'Image not found.'}, status=404)
            except CustomUser.DoesNotExist:
                return JsonResponse({'Message': 'User not found.'}, status=403)
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

class RegenerateImageView(View):
    def regen_image(self, request):
        # Retrieve image ID from the request data
        image_id = request.POST.get('image_id')
        # Get user ID from the request (assuming you have authentication implemented)
        user_id = get_user_id_from_token(request)
        if user_id:
            try:
                # Fetch the original image details from the database
                original_image = Image.objects.get(id=image_id, user__id=user_id)
                # Apply your regeneration logic here
                regenerated_image = self.regenerate_image_logic(original_image)
                # Calculate the regenerative_at datetime based on frequency and frequency_type
                regenerative_at = self.calculate_regenerative_at(original_image)
                # Save the regenerated image to S3 and database
                user = CustomUser.objects.filter(id=user_id).first()
                self.save_to_s3(regenerated_image, original_image, user, regenerative_at)
                return JsonResponse({'message': 'Regenerated image saved successfully'}, status=200)
            except Image.DoesNotExist:
                return JsonResponse({'error': 'Image not found'}, status=404)
        else:
            return JsonResponse({'error': 'User not authenticated'}, status=401)

    def regenerate_image_logic(self, original_image):
        # Implement your regeneration logic here
        # For example, you can use PIL to apply transformations to the original image
        # Here's a simple example:
        regenerated_image_data = original_image.photo.read()  # Read the binary data of the original image
        regenerated_image = PILImage.open(BytesIO(regenerated_image_data))  # Open the image using PIL
        # Apply any desired transformations (e.g., resizing, filtering, etc.)
        # Example: regenerated_image = regenerated_image.resize((new_width, new_height))
        return regenerated_image

    def calculate_regenerative_at(self, original_image):
        # Calculate the next regenerative_at datetime based on frequency and frequency_type
        frequency = original_image.frequency
        frequency_type = original_image.frequency_type
        if frequency_type == 'day':
            regenerative_at = datetime.now() + timedelta(days=frequency)
        elif frequency_type == 'week':
            regenerative_at = datetime.now() + timedelta(weeks=frequency)
        elif frequency_type == 'month':
            regenerative_at = datetime.now() + timedelta(days=30 * frequency)
        elif frequency_type == 'year':
            regenerative_at = datetime.now() + timedelta(days=365 * frequency)
        else:
            # Handle unsupported frequency_type
            regenerative_at = None
        return regenerative_at

    def save_to_s3(self, image, original_image, user, regenerative_at):
        # Connect to your S3 bucket using Boto3
        s3 = boto3.client('s3', aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        original_image_name=original_image.url.split(".png")[0].split('/')[-1]
        # Convert the regenerated image to binary data
        with BytesIO() as buffer:
            image.save(buffer, format='PNG')  # Adjust the format as needed
            buffer.seek(0)
            # Upload the binary data to your S3 bucket
            s3.upload_fileobj(buffer, settings.AWS_STORAGE_BUCKET_NAME2, f'regenerated_image_{original_image_name}.png')  # Adjust the filename as needed
        # Save the regenerated image details to the database
        regenerated_image = RegeneratedImage.objects.create(
            user=user,
            original_image_name=original_image_name,
            regenerated_image=f'regenerated_image_{original_image_name}.png',
            regenerative_at=datetime.now(),
            public=original_image.public,
            nextregeneration_at=regenerative_at)
        # Optionally, perform any additional processing or logging
