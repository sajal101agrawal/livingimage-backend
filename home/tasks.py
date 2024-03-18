# tasks.py
from livingimage.celery import Celery
from celery import shared_task
#from home.models import *
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
#import logging


app = Celery('tasks', broker='redis://127.0.0.1:6379/0')

# Set the pool option to 'threads'
app.conf.update(
    task_default_queue='default',
    task_default_exchange='default',
    task_default_routing_key='default',
    worker_pool='threads',
)

# from celery import shared_task



# @app.task
# @shared_task
def regenerate_image(image_id):
    from home.models import Image, RegeneratedImage, openai_account
    from home.views import calculate_regeneration_time

    # LOGIC FUNCTION
    def preprocess_image(image_path, target_size=(1024, 1024)):
        from PIL import Image
        import io
        print("Hi, I am here")
        # Open the image file
        with Image.open(image_path) as img:
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



    def generate_image(prompt, image_path):
        # Preprocess the image
        openai_api_key=openai_account.objects.first()
        api_key=openai_api_key.key
        preprocessed_image = preprocess_image(image_path)
        client = OpenAI(api_key=api_key)

        # Generate image based on prompt and preprocessed image
        response = client.images.edit(
            model="dall-e-2",
            image=preprocessed_image,
            prompt=prompt,
            n=1,
            size="1024x1024"
        )

        # Extract URL of the generated image from the API response
        generated_image_url = response.data[0].url

        return generated_image_url


    def regenerate_image_logic(original_image):
        prompt=original_image.prompt
        image_path=original_image.photo
        regenerated_image_url = generate_image(prompt, image_path)
        #return regenerated_image
        return  regenerated_image_url

    def save_to_s3(image, original_image, user, regenerative_at_):
        #now_utc = datetime.now(pytz.utc)
        # Connect to your S3 bucket using Boto3
        s3 = boto3.client('s3', aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        original_image_name=original_image.image_name
        # Convert the regenerated image to binary data
        # with BytesIO() as buffer:
            # Download the image data from the URL
        image_data = requests.get(image).content

        # Wrap the image_data in a BytesIO object
        image_buffer = BytesIO(image_data)
        
        # Upload the binary data to your S3 bucket
        s3.upload_fileobj(image_buffer, settings.AWS_STORAGE_BUCKET_NAME2, f'regenerated_image_{original_image_name}.png')

        regenerated_image = RegeneratedImage.objects.create(
            user=user,
            original_image_name=original_image_name,
            original_image_id=original_image.id,
            regenerated_image=f'regenerated_image_{original_image_name}.png',
            regenerated_at=datetime.now(pytz.utc),
            public=original_image.public,
            nextregeneration_at=regenerative_at_)
        

        original_image.regenerated_at = datetime.now(pytz.utc)
        original_image.nextregeneration_at = regenerative_at_
        original_image.save()

    # LOGIC FUNCTION


    



    try:
        original_image = Image.objects.get(id=image_id)
        # Call the logic to regenerate and save the image here

        # LOGIC 

        # Fetch the original image details from the database
        #original_image = Image.objects.get(id=image_id, user__id=user_id)
        # Apply your regeneration logic here
        regenerated_image = regenerate_image_logic(original_image)
        # Calculate the regenerative_at datetime based on frequency and frequency_type
        regenerative_at_ = calculate_regeneration_time(original_image.frequency,original_image.frequency_type)
        # Save the regenerated image to S3 and database
        user = original_image.user  #  CustomUser.objects.filter(id=user_id).first()
        save_to_s3(regenerated_image, original_image, user, regenerative_at_)
        return JsonResponse({'Message': f'Regenerated image {image_id} successfully'}, status=200)
    
        # LOGIC 

        #return {'Message': f'Regenerated image {image_id} successfully'}
    except Image.DoesNotExist:
        return {'Message': 'Image not found'}


# @app.task#(name="Find_Next_Regen_Datetime")
# def find_next_regeneration_datetime():
#     from home.models import Image 
#     # Query the database for images whose nextregeneration_at time has passed
#     images_to_regenerate = Image.objects.filter(nextregeneration_at__lte=datetime.now(pytz.utc))
    
#     # Schedule regeneration tasks for each image
#     for image in images_to_regenerate:
#         regenerate_image.apply_async(args=[image.id], countdown=0)  # Execute immediately

# Get the logger
#logger = logging.getLogger(__name__)



@shared_task
def find_next_regeneration_datetime():
    logger.info("Received task to find next regeneration datetime.")  
    try:
        from home.models import Image 
        from datetime import timedelta
        images_to_regenerate = Image.objects.all()
        # # Schedule regeneration tasks for each image
        # for image in images_to_regenerate:
        #     # Assuming you have defined a task named 'regenerate_image'
        #     task = regenerate_image.apply_async(args=[image.id])
        #     logger.info(f"Scheduled regeneration task for image ID: {image.id}, Task ID: {task.id}")

        return f'Scheduled regeneration tasks for {len(images_to_regenerate)} images'
    except:
        return "Error Happend"



    # Calculate the datetime range for 30 minutes interval      #  IMAGE MODEL OBJECT .ALL RETURN 
    # now = datetime.now(pytz.utc)
    # time_before = now - timedelta(minutes=15)
    # time_after = now + timedelta(minutes=15)
    
    # # Query the database for images within the 30 minutes interval
    # images_to_regenerate = Image.objects.filter(
    #     nextregeneration_at__gte=time_before,
    #     nextregeneration_at__lte=time_after
    # )
    # logger.info("trying to find Image")
    
    # # Schedule regeneration tasks for each image
    # for image in images_to_regenerate:
    #     logger.info(f"Scheduling regeneration task for image ID: {image.id}")
    #     regenerate_image.apply_async(args=[image.id], countdown=0)  # Execute immediately

# @app.task
# def addi(x,y):
#     return x+y
import logging

# Initialize the logger
logger = logging.getLogger(__name__)

# Set the logging level
logger.setLevel(logging.INFO)

# Define a handler to control the log output
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)

# Define a formatter to format the log messages
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)





#logger = logging.getLogger(__name__)

# @shared_task
# def addi(x, y):
#     logger.info(f"Adding {x} and {y}")
#     result = x + y
#     logger.info(f"Result: {result}")
#     return result






# @app.task
# def addi():
#     lst=[]
#     for i in range(1,11):
#         print(i)
#         lst.append(i)
        
#     return "Done"