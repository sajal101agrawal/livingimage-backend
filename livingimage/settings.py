"""
Django settings for livingimage project.

Generated by 'django-admin startproject' using Django 4.2.10.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
import os
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-9nv*%!5^r@a6&@iifvfa5n802t$=d&rm6$a%$vt7u1!x&*ucu='

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['34.226.125.136','127.0.0.1','api.livingimage.io']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'home',
    'rest_framework_simplejwt',
    'rest_framework',
    'django_crontab',
    'corsheaders',
    'django_celery_beat',
    'django_celery_results',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'livingimage.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'livingimage.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

#STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'





STATIC_URL = '/static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'




EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtpout.secureserver.net'  # GoDaddy SMTP server
EMAIL_PORT = 465  # Use 465 for SSL/TLS
EMAIL_USE_SSL = True  # Enable SSL/TLS encryption
EMAIL_HOST_USER = 'support@livingimage.io'  # Your GoDaddy email address
EMAIL_HOST_PASSWORD = '@Livingimage123'  # Your GoDaddy email password

 


# In settings.py
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'  # or 'django.db.models.BigAutoField'



REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',

}

CORS_ALLOW_ALL_ORIGINS = True  
AUTH_USER_MODEL = "home.CustomUser"
# AUTH_USER_MODEL = 'account.User'

LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "home"


import configparser

config = configparser.ConfigParser()
config.read('config.ini')

AWS_ACCESS_KEY_ID = config['AWS']['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = config['AWS']['AWS_SECRET_ACCESS_KEY']

STRIPE_PUBLIC_KEY = config['AWS']['STRIPE_PUBLIC_KEY']
STRIPE_SECRET_KEY = config['AWS']['STRIPE_SECRET_KEY']
STRIPE_WEBHOOK_SECRET = config['AWS']['STRIPE_WEBHOOK_SECRET']


AWS_STORAGE_BUCKET_NAME = 'livingimage-original-images'
AWS_STORAGE_BUCKET_NAME2 = 'livingimage-regenerated-images'
AWS_STORAGE_BUCKET_NAME3 = 'livingimage-profile-bucket'
AWS_S3_SIGNATURE_VERSION = 's3v4'
#AWS_S3_SIGNATURE_NAME = 's3v4',
AWS_S3_REGION_NAME = 'us-east-1'
AWS_S3_FILE_OVERWRITE = True
AWS_DEFAULT_ACL =  'public-read'  # Adjusted   from None
AWS_S3_VERIFY = True
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'


# Set the maximum size for in-memory file uploads to 20 MB (20 * 1024 * 1024 bytes)
MAX_IMAGE_SIZE_MB = 20

# Celery Broker URL
#CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'

# Celery Task Serialization Configuration
CELERY_ACCEPT_CONTENT = ['application/json']  # Define the accepted content types for tasks
CELERY_TASK_SERIALIZER = 'json'   # Set the task serializer to JSON
CELERY_RESULT_SERIALIZER = 'json' # Set the result serializer to JSON
CELERY_ENABLE_UTC=True




CELERY_RESULT_BACKEND = 'django-db'
CELERY_TIMEZONE = 'UTC'
#from home.tasks import find_next_regeneration_datetime

# Run this task periodically to check for images that need regeneration
CELERY_BEAT_SCHEDULE = {
    'Find_Next_Regen_Datetime': {
        'task': 'home.tasks.find_next_regeneration_datetime',
        'schedule': 10,  # Execute every 60 seconds (adjust as needed)
    },
}


CELERY_TASK_TRACK_STARTED=True
YOUR_DOMAIN=config['AWS']['YOUR_DOMAIN']
