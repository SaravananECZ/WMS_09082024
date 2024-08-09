from django.contrib import admin
from django.urls import include, path
urlpatterns = [
    path('admin/', admin.site.urls),
    path('polls/', include('polls.urls')),
    path('accounts/', include('accounts.urls')),
    path('warehouse/', include('Warehouse_Management.urls')),
]
# urlpatterns = [
#     path('admin/', admin.site.urls),

#     path('polls/', include('polls.urls')),
#     path('accounts/', include('accounts.urls')),
#     path('warehouse/', include('Warehouse_Management.urls')), ]
