# Generated by Django 4.2.11 on 2024-04-15 14:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0018_regeneratedimage_original_image_key_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='profile_photo',
            field=models.ImageField(default='default_profile.jpg', upload_to='profile_pic/'),
        ),
    ]