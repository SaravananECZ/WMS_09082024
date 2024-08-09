from django import forms
from .models import WarehouseDetails


class WarehouseDetailsForm(forms.ModelForm):
    class Meta:
        model = WarehouseDetails
        fields = ['Warehouse_Name', 'Warehouse_location', 'no_of_floors_available', 'Warehouse_square_feet','ground_floor_square_feet', 'first_floor_square_feet', 'Warehouse_amount', 'Warehouse_image', 'Additional_amount', 'permitted_items', 'prohibited_items']
      