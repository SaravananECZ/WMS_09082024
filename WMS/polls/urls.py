# polls/urls.py

from django.urls import path
from .views import add_question 
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('add/', views.add_question, name='add_question'),
    path('<int:question_id>/', views.detail, name='detail'),
    # Add other paths as needed
]
