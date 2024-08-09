from django.urls import path
from . import views

app_name = 'warehouse_management'

urlpatterns = [
    path('create/', views.create_warehouse, name='create_warehouse'),
    path('search/', views.search_view, name='search'),
    path('role-selection/', views.role_selection_view, name='RoleSelection'),

    path('warehouse-owner-details/', views.Warehouse_details_view, name='warehouse_owner_details'),
]