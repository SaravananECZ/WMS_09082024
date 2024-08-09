# accounts/forms.py
from django.contrib.auth import get_user_model
from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(max_length=100)
    password = forms.CharField(widget=forms.PasswordInput)

class CustomUserForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ['CompanyName_MCU', 'MCANumber_MCU', 'GSTNumber_MCU', 'PanNumber_MCU', 'Emailid_MCU', 'Contact_MCU', 'Address_MCU']
