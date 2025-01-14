# Generated by Django 5.0.6 on 2024-07-05 10:02

import phonenumber_field.modelfields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', phonenumber_field.modelfields.PhoneNumberField(max_length=128, region=None, unique=True)),
                ('otp', models.CharField(blank=True, max_length=6)),
                ('otp_created_at', models.DateTimeField(blank=True, null=True)),
            ],
        ),
    ]
