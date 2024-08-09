from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.db import models
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    



class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  
    Phone_number = models.CharField(max_length=15, blank=True, null=True)  
    CreatedOn = models.DateTimeField(default=timezone.now)  
    Manufacturing_cu = models.CharField(max_length=255,blank=True,null=True)
    MCU_CreatedOn = models.DateTimeField(default=timezone.now)  
    Warehouse_cu = models.CharField(max_length=255,blank=True,null=True)
    WCU_CreatedOn = models.DateTimeField(default=timezone.now)  
    
    GSTNumber_MCU = models.CharField(max_length=255,blank=True,null=True)
    MCANumber_MCU = models.CharField(max_length=255,blank=True,null=True)
    CompanyName_MCU = models.CharField(max_length=255,blank=True,null=True)
    PanNumber_MCU = models.CharField(max_length=255,blank=True,null=True)
    Emailid_MCU = models.CharField(max_length=255,blank=True,null=True)
    Contact_MCU = models.CharField(max_length=255,blank=True,null=True)
    Address_MCU = models.CharField(max_length=255,blank=True,null=True)

    WDRANumber_WCU = models.CharField(max_length=255,blank=True,null=True)
    AadharNumber_WCU = models.CharField(max_length=255,blank=True,null=True)
    CompanyName_WCU = models.CharField(max_length=255,blank=True,null=True)
    PanNumber_WCU = models.CharField(max_length=255,blank=True,null=True)
    Emailid_WCU = models.CharField(max_length=255,blank=True,null=True)
    Contact_WCU = models.CharField(max_length=255,blank=True,null=True)
    Address_WCU = models.CharField(max_length=255,blank=True,null=True)

    
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email and password are required

    def __str__(self):
        return self.email
