# In views.py
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import WarehouseDetailsForm
from django.shortcuts import render
def search_view(request):
    return render(request, 'search.html')



def role_selection_view(request):
    # Your view logic here
    return render(request, 'role_selection.html')

def success(request):
    return render(request, 'success.html')
def Warehouse_details_view(request):
    # Your view logic here
    return render(request, 'WarehouseDetails.html')

def create_warehouse(request):
    if request.method == 'POST':
        form = WarehouseDetailsForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('success_url')  # Redirect to a success page or another view
    else:
        form = WarehouseDetailsForm()
    
    return render(request, 'warehouse_form.html', {'form': form})


    