# Generated by Django 4.2.11 on 2024-03-11 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0009_image_nextregeneration_at_image_regenerated_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='history',
            name='image_name',
            field=models.CharField(default='prior_to_image_name', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='image',
            name='image_name',
            field=models.CharField(default='prior_to_image_name', max_length=255),
            preserve_default=False,
        ),
    ]