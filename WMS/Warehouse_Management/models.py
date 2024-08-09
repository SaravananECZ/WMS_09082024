from django.db import models
from accounts.models import CustomUser
from django import forms



class WarehouseDetails(models.Model):
    Warehouse_Name = models.CharField(max_length=100)
    Warehouse_location = models.CharField(max_length=100)
    no_of_floors_available = models.CharField(max_length=20, choices=[('Ground', 'Ground Floor'), ('First', 'First Floor')])
    Warehouse_square_feet = models.IntegerField()
    ground_floor_square_feet = models.IntegerField(blank=True, null=True)
    first_floor_square_feet = models.IntegerField(blank=True, null=True)
    Warehouse_amount = models.DecimalField(max_digits=10, decimal_places=2)
    Warehouse_image = models.ImageField(upload_to='warehouse_images/', null=True, blank=True)
    Additional_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    permitted_items = models.JSONField(default=list)  
    prohibited_items = models.JSONField(default=list)  

    
    def __str__(self):
        return self.Warehouse_Name
class Item(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()

    def __str__(self):
        return self.name