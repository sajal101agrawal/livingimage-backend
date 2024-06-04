# tasks.py
from livingimage.celery import Celery
from celery import shared_task
from home.models import CreditHistory
# from home.views import calculate_regeneration_time
from django.conf import settings
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
import pytz
from openai import OpenAI
import requests
from io import BytesIO
from django.http import JsonResponse
import logging


app = Celery('tasks', broker='redis://127.0.0.1:6379/0')
# Configure logging to write to a file
logging.basicConfig(filename='celery.log', level=logging.INFO)

# Set the pool option to 'threads'
app.conf.update(
    task_default_queue='default',
    task_default_exchange='default',
    task_default_routing_key='default',
    worker_pool='threads',
)

# from celery import shared_task



# @app.task
@shared_task
def regenerate_image(image_id):
    from home.models import Image, RegeneratedImage, openai_account
    from home.views import calculate_regeneration_time

    # img_main = Image.objects.filter(id=image_id).first()
    # user = img_main.user
        # if user.credit < 1:
        #     msg = 'Insufficient credit to perform this action.'
        #     return Response({"Message": msg}, status=status.HTTP_402_PAYMENT_REQUIRED)


    # LOGIC FUNCTION
    # def preprocess_image(image_path, target_size=(1024, 1024)):
    #     from PIL import Image
    #     import io
    #     print("Hi, I am here")
    #     # Open the image file
    #     with Image.open(image_path) as img:
    #         # Convert image to RGBA mode
    #         img = img.convert("RGBA")
    #         # Resize the image
    #         resized_img = img.resize(target_size)
    #         # Create a BytesIO object to store the image data
    #         img_byte_array = io.BytesIO()
    #         # Save the image to the BytesIO object in PNG format
    #         resized_img.save(img_byte_array, format="PNG")
    #         # Get the bytes from the BytesIO object
    #         processed_image = img_byte_array.getvalue()
    #     return processed_image


    def preprocess_image(image_path, target_size=(1024, 1024)):
        from PIL import Image
        import io
        print("Hi, I am here")
        print("Downloading image from:", image_path)
        print("THe image path is ",image_path)
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



    # def generate_image(image_path):
    #     openai_api_key=openai_account.objects.first()
    #     api_key=openai_api_key.key
    #     preprocessed_image = preprocess_image(image_path)
    #     client = OpenAI(api_key=api_key)
    #     response = client.images.create_variation(
    #     image=preprocessed_image,
    #     n=2,
    #     size="1024x1024"
    #     )

    #     # Extract URL of the generated image from the API response
    #     generated_image_url = response.data[0].url

    #     return generated_image_url
    

    def generate_image(image_path,prompt):
        print("Inside the generate image function")

        # Preprocess the image
        openai_api_key=openai_account.objects.first()
        api_key=openai_api_key.key

        client = OpenAI(api_key=api_key)
        
        print("The imaeg path is ",image_path)


        if image_path is not None:
            print("prior preprocess")
            preprocessed_image = preprocess_image(str(image_path))
            print("after preprocess")

            response = client.images.create_variation(
            image=preprocessed_image,
            n=2,
            size="1024x1024"
            )
            print("The image path is wokring 222222222222222222222222",image_path)

        else:
            print("Might have worked")
            response = client.images.generate(
            model="dall-e-3",
            prompt=prompt,
            size="1024x1024",
            quality="standard",
            n=1,
            )


        generated_image_url = response.data[0].url

        print("The generated image url: ",generated_image_url)

        return generated_image_url


    # def regenerate_image_logic(original_image):
    #     #prompt=original_image.prompt
    #     image_path=str(original_image.photo)
    #     regenerated_image_url = generate_image(image_path)
    #     return  regenerated_image_url
    
    def regenerate_image_logic(original_image):
        # if original_image.photo and str(original_image.photo) != "":
        #     image_path = str(original_image.photo)
        # else:
        #     image_path = None

        image_path = original_image.photo if original_image.photo else None    

        print("GONE FROM HERE")


        prompt = original_image.prompt
        print("The Prompt is: ",prompt)
        regenerated_image_url = generate_image(image_path,prompt)
        print("After the generate iamge function")
        return  regenerated_image_url

    def save_to_s3(image_url, original_image, user, regenerative_at_):        
        s3 = boto3.client('s3', aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        original_image_id = original_image.id
        original_image_name = original_image.image_name

        user = original_image.user
        if user.credit < 1:
            msg = 'Insufficient credit to perform this action.'
            return {"Message": msg}

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

    # LOGIC FUNCTION

    try:
        original_image = Image.objects.get(id=image_id)

        # img_main = Image.objects.filter(id=image_id).first()
        user = original_image.user
        if user.credit < 1:
            msg = 'Insufficient credit to perform this action.'
            return {"Message": msg}
        
        # Call the logic to regenerate and save the image here

        # LOGIC 
        # Apply your regeneration logic here
        regenerated_image = regenerate_image_logic(original_image)
        print("The regenerated Image URL is:",regenerated_image)
        print("I AM WORKING TILL HERE REGENERATE IMAGE LOGIC")
        # Calculate the regenerative_at datetime based on frequency and frequency_type
        regenerative_at_ = calculate_regeneration_time(original_image.frequency,original_image.frequency_type)
        print("I AM WORKING TILL HERE CALCULATE REGENERATE TIME")
        # Save the regenerated image to S3 and database
        user = original_image.user  #  CustomUser.objects.filter(id=user_id).first()
        print("I AM getting user",user)

        save_to_s3(regenerated_image, original_image, user, regenerative_at_)
        print("I AM WORKING TILL THE LAST OF CODE")

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
        return {'Message': f'Regenerated image {image_id} successfully'}
    
        # LOGIC 

        #return {'Message': f'Regenerated image {image_id} successfully'}
    except Image.DoesNotExist:
        return {'Message': 'Image not found'}



# Get the logger
logger = logging.getLogger(__name__)



@shared_task
def find_next_regeneration_datetime():
    logger.info("Received task to find next regeneration datetime.")  
 
    try:
        from home.models import Image 
        from datetime import timedelta
        # Calculate the datetime range for 30 minutes interval      #  IMAGE MODEL OBJECT .ALL RETURN 
        now = datetime.now(pytz.utc)
        time_before = now - timedelta(seconds=10)
        time_after = now + timedelta(seconds=10)
        
        # Query the database for images within the 30 minutes interval
        images_to_regenerate = Image.objects.filter(
            nextregeneration_at__gte=time_before,
            nextregeneration_at__lte=time_after
        )
        logger.info("trying to find Image")
    
        # Schedule regeneration tasks for each image
        for image in images_to_regenerate:
            logger.info(f"Scheduling regeneration task for image ID: {image.id}")
            regenerate_image.apply_async(args=[image.id], countdown=0)  # Execute immediately
        return f'Scheduled regeneration tasks for {len(images_to_regenerate)} images'
    
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return "An error occurred during regeneration task scheduling."