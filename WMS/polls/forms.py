# polls/forms.py

from django import forms
from .models import Question

class QuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ['question_text', 'pub_date']  # Include pub_date field if necessary
        # widgets = {'pub_date': forms.HiddenInput()}  # Optionally hide pub_date if auto_now_add=True
