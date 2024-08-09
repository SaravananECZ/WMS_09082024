# polls/views.py
from .models import Question
from .forms import QuestionForm
from django.shortcuts import render,redirect
from .models import Question
from django.utils import timezone

def add_question(request):
    if request.method == 'POST':
        form = QuestionForm(request.POST)
        if form.is_valid():
            question = form.save(commit=False)
            question.pub_date = timezone.now()  # Set pub_date to current datetime
            question.save()
            return redirect('index')  # Redirect to index page after successful form submission
    else:
        form = QuestionForm()
    
    return render(request, 'polls/add_question.html', {'form': form})


def index(request):
    latest_questions = Question.objects.order_by('-pub_date')[:5]
    context = {'latest_questions': latest_questions}
    return render(request, 'polls/index.html', context)

def detail(request, question_id):
    question = Question.objects.get(pk=question_id)
    return render(request, 'polls/detail.html', {'question': question})
