from django import forms
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm, PasswordResetForm
from .models import *

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    phone_number = forms.CharField(max_length=15, required=False)
    first_name = forms.CharField(label="", max_length=100, widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'First Name'}))
    last_name = forms.CharField(label="", max_length=100, widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Last Name'}))

    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', 'user_type', 'phone_number')

    def save(self, commit=True):
        # Call the parent save method to save the password and other base fields
        user = super().save(commit=False)
        # Add additional fields to the user instance
        user.email = self.cleaned_data['email']
        user.phone_number = self.cleaned_data['phone_number']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.user_type = self.cleaned_data['user_type']
        
        # Save the user instance to the database
        if commit:
            user.save()
        return user

class UserLoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)



class AppointmentSlotForm(forms.ModelForm):
    class Meta:
        model = AppointmentSlot
        fields = ['doctor', 'room', 'day', 'start_time', 'end_time', 'is_available']
        widgets = {
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')

        # Validate that the end time is after the start time
        if start_time and end_time and end_time <= start_time:
            raise forms.ValidationError("End time must be after the start time.")

        return cleaned_data
    

class DoctorProfileForm(forms.ModelForm):
    class Meta:
        model = Doctor
        fields = ['specialization', 'qualifications', 'experience', 'consultation_fee', 'profile_picture']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the widget and queryset for specialization field
        self.fields['specialization'].widget = forms.CheckboxSelectMultiple()
        self.fields['specialization'].queryset = Specialization.objects.all()


    def clean(self):
        cleaned_data = super().clean()
        specialization = cleaned_data.get('specialization')
        
        # Example validation: Ensure at least one specialization is selected
        if not specialization:
            raise forms.ValidationError("Please select at least one specialization.")
        
        return cleaned_data
    

class UserForm(forms.ModelForm):
     class Meta:
          model = User
          fields = ['first_name', 'last_name', 'email', 'phone_number']



class PatientForm(forms.ModelForm):
     class Meta:
          model = Patient
          fields = ['date_of_birth', 'blood_group', 'gender', 'medical_history']
          widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
            'medical_history': forms.Textarea(attrs={'rows': 4}),
          }


class PatientProfileForm(forms.ModelForm):
     class Meta:
          model = PatientProfile
          fields = ['address_1', 'address_2', 'city', 'country', 'profile_picture']

    


class AppointmentForm(forms.ModelForm):
    class Meta:
        model = Appointment
        fields = [ 'slot']

    def clean(self):
        cleaned_data = super().clean()
        slot = cleaned_data.get('slot')

        # Validate that the slot belongs to the selected doctor
        """ if slot and doctor and slot.doctor != doctor:
            raise forms.ValidationError("The selected slot does not belong to the selected doctor.") """

        # Validate that the slot is available
        if slot and not slot.is_available:
            raise forms.ValidationError("The selected slot is not available.")

        return cleaned_data
    


class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['prescription_text', 'additional_notes',]
        widgets = {
            'prescription_text': forms.Textarea(attrs={'rows': 4}),
            'additional_notes': forms.Textarea(attrs={'rows': 4}),
        }

    """ def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Customize the appointment field queryset if needed
        self.fields['appointment'].queryset = Appointment.objects.filter(status='completed') """



class DiagnosticReportForm(forms.ModelForm):
    class Meta:
        model = DiagnosticReport
        fields = [ 'report_file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter a description...'}),
            'report_file': forms.ClearableFileInput(attrs={'accept': '.docx,.pdf,.jpg,.png'}),  # Restrict file types
        }
        labels = {
            'report_file': 'Upload Report',
            'description': 'Report Description',
        }



class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['rating', 'comment']
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter your feedback...'}),
            'rating': forms.NumberInput(attrs={'min': 1, 'max': 5}),
        }
        labels = {
            'rating': 'Rating (1-5)',
            'comment': 'Your Feedback',
        }



class ChangePasswordForm(SetPasswordForm):
	class Meta:
		model = User
		fields = ["new_password1", "new_password2"]

	def __init__(self, *args, **kwargs):
		super(ChangePasswordForm, self).__init__(*args, **kwargs)

		self.fields['new_password1'].widget.attrs['class'] = 'form-control'
		self.fields['new_password1'].widget.attrs['placeholder'] = 'Password'
		self.fields['new_password1'].label = ''
		self.fields['new_password1'].help_text = '<ul class="form-text text-muted small"><li>Your password can\'t be too similar to your other personal information.</li><li>Your password must contain at least 8 characters.</li><li>Your password can\'t be a commonly used password.</li><li>Your password can\'t be entirely numeric.</li></ul>'

		self.fields['new_password2'].widget.attrs['class'] = 'form-control'
		self.fields['new_password2'].widget.attrs['placeholder'] = 'Confirm Password'
		self.fields['new_password2'].label = ''
		self.fields['new_password2'].help_text = '<span class="form-text text-muted"><small>Enter the same password as before, for verification.</small></span>'





class ResetPasswordForm(PasswordResetForm):
	class Meta:
		model = User
		fields = ["new_password1", "new_password2"]

	def __init__(self, *args, **kwargs):
		super(ChangePasswordForm, self).__init__(*args, **kwargs)

		self.fields['new_password1'].widget.attrs['class'] = 'form-control'
		self.fields['new_password1'].widget.attrs['placeholder'] = 'Password'
		self.fields['new_password1'].label = ''
		self.fields['new_password1'].help_text = '<ul class="form-text text-muted small"><li>Your password can\'t be too similar to your other personal information.</li><li>Your password must contain at least 8 characters.</li><li>Your password can\'t be a commonly used password.</li><li>Your password can\'t be entirely numeric.</li></ul>'

		self.fields['new_password2'].widget.attrs['class'] = 'form-control'
		self.fields['new_password2'].widget.attrs['placeholder'] = 'Confirm Password'
		self.fields['new_password2'].label = ''
		self.fields['new_password2'].help_text = '<span class="form-text text-muted"><small>Enter the same password as before, for verification.</small></span>'
