# celery.py
import os
from celery import Celery

# Set the Celery app
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'livingimage.settings')
app = Celery('livingimage')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Set Celery to use UTC timezone
# app.conf.timezone = 'UTC'

# app.conf.timezone = 'Asia/Kolkata'
