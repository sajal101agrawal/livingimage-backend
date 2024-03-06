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

# Create your views here.

#----------------------Code copied from Keywordlit Project--------------------------------------------------------------

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
      

# class UserRegistrationView(APIView):
#     """ 
#     An api view for user registration and return error if these is any error or not provided insufficient data
#     """
#     renderer_classes = [UserRenderer]
#     def post(self, request, format=None):
#         if not 'username' in request.data :
#             while True :
#                 genrated_random_username =  generate_random_string(15)
#                 if CustomUser.objects.filter(username=genrated_random_username).count() == 0 :
#                     request.data['username'] = genrated_random_username
#                     break
#         serializer = UserRegistrationSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         if not request.data['email'] :
#             return Response({'Message':'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
#         user = serializer.save()
#         if 'super' in request.data and request.data['super'] is True : 
#             user.is_superuser = True
#             user.save()
#         #token = get_tokens_for_user(user)
#         verification_code = random.randint(100000,999999)
#         user.verification_code = verification_code
#         user.save()

#         # subject = 'Verification code is here'
#         # message = f'verification code : {verification_code}'
#         # from_email = 'info@keywordlit.com'
#         # recipient_list = [user.email]   

#         # send_mail(subject, message, from_email, recipient_list)            
#         # #return Response({'token':token, "email" : 'email verification code has been set' ,'msg':'Registration succesful'}, status=status.HTTP_201_CREATED)
#         # return Response({"email" : 'Email verification code has been set' ,'Message':'Verify your account'}, status=status.HTTP_201_CREATED)

#         try:
#             send_otp_via_email(user.email)  # Use your send_otp_via_email function
#         except ValidationError as e:
#             return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

#         return Response({"email": 'Email verification code has been set', 'Message': 'Verify your account'},
#                         status=status.HTTP_201_CREATED)




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
        
        for history in History.objects.filter(user=user) :
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
                'image_data' : history.image_data.url,
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
            'Image_history' : Image_history,
            'deposit_history' : diposit_history
        }
        response = Response(jsonn_response, status=status.HTTP_200_OK)
        
        # Set the Referrer Policy header
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response


# class UserModifyPasswordView(APIView):
#     """ 
#     Change Existing user password
#     """
#     renderer_classes = [UserRenderer]
#     permission_classes = [IsAuthenticated]

#     def post(self, request, format=None):
#       user_id = get_user_id_from_token(request)
#       user = CustomUser.objects.filter(id=user_id).first()
#       print("the user is",user.email)
#       serializer = UserModifyPasswordSerializer(data=request.data)
#       serializer.is_valid(raise_exception=True)
      
#       if user.is_user_verified:
#         if not request.data.get('old_password'):
#             return Response({'Message': 'Old Password is required'}, status=status.HTTP_400_BAD_REQUEST)

#         if not request.data.get('new_password'):
#             return Response({'Message': 'New Password is required'}, status=status.HTTP_400_BAD_REQUEST)

#         is_superuser = request.data.get('super', False)
#         if is_superuser:
#             user = CustomUser.objects.create_superuser(**serializer.validated_data)
#             user.is_user_verified = True  # ALL superuser are verified
#             user.save()
#             return Response({"email": 'Email is verified', 'Message': 'Admin user Created'},
#                             status=status.HTTP_201_CREATED)
#       else:
#           return Response({'Message': 'Email is not verified!'}, status=status.HTTP_400_BAD_REQUEST)



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



class DashboardView(View):
    def get(self, request):
        img = Image.objects.all()
        return render(request, "myapp/dashboard.html", {"img": img})

class DeleteImageView(View):
    def get(self, request, id):
        img = Image.objects.get(id=id)
        img.delete()
        return redirect('/dashboard/')

class SuperDashboardView(View):
    def get(self, request):
        img = Image.objects.all()
        return render(request, "myapp/dashboard.html", {"img": img})




# def upload_image(request):
#  if request.method=="POST":
#   form = ImageForm(request.POST, request.FILES)
#   if form.is_valid():
#     form.save()
#  form = ImageForm()# In this Prompt and Frequency will also Go here
#  return render(request, 'myapp/upload.html', {'form':form})


# def dashboard_view(request):
#  img = Image.objects.all()
#  return render(request,"myapp/dashboard.html",{"img":img})

# def delete_image(request, id): # Only Admin Functionality for Now
 
#  img=Image.objects.get(id=id)
#  img.delete()
#  return redirect('/dashboard/')


# # def update_image(request, id): # Only Admin Functionality for Now
 
# #  img=Image.objects.get(id=id)
# #  img.update()
# #  return redirect('/dashboard/')

# def superdashboard_view(request): # Admin Dashboard Having update and delete button
#  img = Image.objects.all()
#  return render(request,"myapp/dashboard.html",{"img":img})