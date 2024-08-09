from django.shortcuts import render, redirect
from django.contrib import messages
import random
import string
import smtplib
from django.contrib import messages
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from .models import CustomUser  # Import your model here
from .forms import CustomUserForm  # Ensure this points to the correct form class

from django.shortcuts import render, redirect

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError

from django.shortcuts import render, redirect

from django.contrib import messages
from django.db.utils import IntegrityError
from django.core.exceptions import ValidationError
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from django.urls import reverse
from django.urls import reverse_lazy

def manufacturing_details_view(request):
    User = get_user_model()
    current_user = request.user  # Get the currently logged-in user
    user_name = current_user.email
    print("1")  # Debugging output
    print(user_name)

    if request.method == 'POST':
        form = CustomUser(request.POST)
        if form.is_valid():
            # Extract data from form
            CompanyName_MCU = form.cleaned_data['CompanyName_MCU']
            MCANumber_MCU = form.cleaned_data['MCANumber_MCU']
            GSTNumber_MCU = form.cleaned_data['GSTNumber_MCU']
            PanNumber_MCU = form.cleaned_data['PanNumber_MCU']
            Emailid_MCU = form.cleaned_data['Emailid_MCU']
            Contact_MCU = form.cleaned_data['Contact_MCU']
            Address_MCU = form.cleaned_data['Address_MCU']

            # Debug prints
            print('Company Name:', CompanyName_MCU)
            print('MCANumber_MCU:', MCANumber_MCU)
            print('GST Number:', GSTNumber_MCU)
            print('PAN Number:', PanNumber_MCU)
            print('Emailid_MCU:', Emailid_MCU)
            print('Contact Details:', Contact_MCU)
            print('Address:', Address_MCU)

            # Update the user email if provided
            if Emailid_MCU:
                current_user.email = Emailid_MCU
                current_user.save()
                print('Updated Email:', current_user.email)

            # Here you might want to save other form data or perform other actions
            
            return redirect('success')  # Make sure 'success' is defined in your URL patterns
    else:
        form = CustomUser()

    return render(request, 'manufacturerDetails.html', {'form': form})
def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        # Generate OTP
        otp = generate_otp()
        print(otp)
       
        # Example function to send OTP via email
        send_otp_email(email, otp)
        # Store email and OTP in session for verification
        request.session['otp_email'] = email
        request.session['otp'] = otp
        # Redirect to OTP verification page
        return redirect('verify_otp')
    # If GET request or after form submission
    return render(request, 'accounts/register.html')

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        saved_otp = request.session.get('otp')
        if entered_otp == saved_otp:
            # Clear OTP data from session after successful verification
            email = request.session.get('otp_email')
            del request.session['otp_email']
            del request.session['otp']
            messages.success(request, 'OTP verified successfully. You can now create your account.')
            return redirect('create_account', email=email)
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
    # If GET request or after form submission
    return render(request, 'accounts/verify_otp.html')



def create_account(request, email):
    if request.method == 'POST':
        print("POST request received")
        password = request.POST.get('password')

        if not password:
            print("Password is missing")
            messages.error(request, 'Password is required.')
            return render(request, 'accounts/create_account.html', {'email': email})

        User = get_user_model()  # Fetch the custom user model

        try:
            # Check if a user with this email already exists
            existing_user = User.objects.filter(email=email).first()

            if existing_user:
                # If the user exists, update their password
                print(f"Updating password for existing user with email: {email}")
                existing_user.set_password(password)
                existing_user.save()
                print("Password updated successfully")
                messages.success(request, 'Password updated successfully. You can now log in.')
            else:
                # Create a new user if no existing user is found
                print(f"Attempting to create user with email: {email}")
                user = User.objects.create_user(email=email, password=password)
                print("User created successfully")
                messages.success(request, 'Account created successfully. You can now log in.')

            return redirect('login')
        except IntegrityError:
            print("IntegrityError: An account with this email already exists.")
            messages.error(request, 'An account with this email already exists.')
        except ValidationError as e:
            print(f"ValidationError: {e}")
            messages.error(request, f'Error: {e}')
        except Exception as e:
            print(f"Unexpected error: {e}")
            messages.error(request, f'An unexpected error occurred: {e}')

    print("Rendering create_account.html")
    return render(request, 'accounts/create_account.html', {'email': email})


def generate_otp():
    length = 6  # Length of the OTP
    letters_and_digits = string.digits  # Using only digits for OTP
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def send_otp_email(email, otp):
    smtp_server = 'smtpout.secureserver.net'
    smtp_port = 465  # For SSL
    sender_email = 'saravanan@ecosoftzolutions.com'
    receiver_email = email
    password = 'Ecosoft@12345'
    subject = 'OTP Verification'  # Subject with OTP
    body = f"""
    <html>
    <head></head>
    <body>
        <p>Hello,<br>
           This is an OTP email message.<br>
           Your OTP is: {otp}<br>
           Regards,<br>
           Sender
        </p>
    </body>
    </html>
    """

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject
    print(receiver_email)
    message.attach(MIMEText(body, 'html'))

    # Send the email using SMTP with SSL
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

    print("Email sent successfully.")

def Warehouse_details_view(request):
    return render(request, 'WarehouseDetails.html')

def login(request):
    print(f"Request method: {request.method}")
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        print(f"Received username: {username}")
        # Note: Avoid printing passwords in a real application for security reasons.
        print(f"Received password: {'*' * len(password) if password else 'None'}")  # Mask password

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)
            messages.success(request, 'You are now logged in.')
           # return redirect('http://127.0.0.1:8000/warehouse/search/')
            search_url = reverse('warehouse_management:search')
            return redirect(search_url)
        else:
            messages.error(request, 'Invalid username or password.')
    print("Rendering login page")
    return render(request, 'accounts/login.html')
def password_reset(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(f"Received password reset request for email: {email}")
        
        User = get_user_model()  # Fetch the custom user model

        try:
            user = User.objects.get(email=email)  # Use User model class directly
            print(f"User found: {user.email}")
            
            otp = generate_otp()  # Generate OTP
            request.session['otp_email'] = email
            request.session['otp'] = otp
            print(f"Generated OTP: {otp}")
            
            send_otp_email(email, otp)  # Send OTP email
            print(f"OTP sent to: {email}")
            
            messages.success(request, 'An OTP has been sent to your email address.')
        except User.DoesNotExist:
            print(f"Email address not found: {email}")
            messages.error(request, 'Email address not found.')
        except Exception as e:
            print(f"An error occurred: {e}")
            messages.error(request, f'An error occurred: {e}')
        
        return redirect('verify_otp')  # Redirect to prevent form resubmission

    return render(request, 'accounts/password_reset.html')