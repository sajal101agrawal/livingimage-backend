# Generated by Django 4.2.11 on 2024-05-24 10:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0023_membership_customuser_is_subscribed_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='membership',
            name='credits',
            field=models.IntegerField(default=100),
            preserve_default=False,
        ),
    ]