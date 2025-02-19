from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.user_type == 'admin':
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You must be an admin to access this page.')
        return redirect('login')
    return _wrapped_view

def doctor_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.user_type == 'doctor':
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You must be a doctor to access this page.')
        return redirect('login')
    return _wrapped_view

def patient_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.user_type == 'patient':
            return view_func(request, *args, **kwargs)
        messages.error(request, 'You must be a patient to access this page.')
        return redirect('login')
    return _wrapped_view
