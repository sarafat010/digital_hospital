
from django.db import models
import uuid
from datetime import time
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator

class User(AbstractUser):
    """
    Base user model with additional fields for all user types
    """
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('patient', 'Patient')
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name='custom_user_set',  # Changed from user_set
        related_query_name='custom_user'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',  # Changed from user_set
        related_query_name='custom_user'
    )
    def save(self, *args, **kwargs):
        # Set is_superuser and is_staff based on user_type
        if self.user_type == 'admin':
            self.is_superuser = True
            self.is_staff = True
        else:
            self.is_superuser = False
            self.is_staff = False

        # Call the parent class's save method
        super().save(*args, **kwargs)

class AdminProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)



@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        if instance.user_type == 'admin':
            AdminProfile.objects.create(user=instance)
        elif instance.user_type == 'doctor':
            Doctor.objects.create(user=instance)
        elif instance.user_type == 'patient':
            Patient.objects.create(user=instance)

class Specialization(models.Model):

    name = models.CharField(max_length=100, unique=True, help_text="The name of the specialization (e.g., Cardiology).")
    description = models.TextField(blank=True, null=True, help_text="A brief description of the specialization.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="The timestamp when the specialization was created.")

    def __str__(self):
        return self.name  

    class Meta:
        verbose_name = "Specialization"  # Singular name for the model
        verbose_name_plural = "Specializations"  # Plural name for the model
        ordering = ['name']  # Order specializations alphabetically by name

class Doctor(models.Model):
    """
    Doctor profile model with detailed information
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='doctor_profile')
    specialization = models.ManyToManyField(Specialization, blank=True, related_name='doctor_specialization')
    qualifications = models.TextField(blank=True)
    experience = models.IntegerField(blank=True, default=0)
    consultation_fee = models.DecimalField(max_digits=10, decimal_places=2, default=500)
    is_active = models.BooleanField(default=True)
    profile_picture = models.ImageField(upload_to="doctor_profile/", default='default_profile_pic.jpg')

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.specialization}"
    

class Patient(models.Model):
    """
    Patient profile model with medical history and personal details
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='patient')
    date_of_birth = models.DateField(null=True, blank=True)
    blood_group = models.CharField(max_length=250, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[
        ('male', 'Male'), 
        ('female', 'Female'), 
        ('other', 'Other')
    ])
    medical_history = models.TextField(blank=True)
    last_checkup = models.DateField(null=True, blank=True)


    def __str__(self):
        return self.user.get_full_name()
    
@receiver(post_save, sender=Patient)
def create_patient_profile(sender, instance, created, **kwargs):
    """
    Signal to create a PatientProfile whenever a Patient is created.
    """
    if created:
        PatientProfile.objects.create(patient=instance)

    
class PatientProfile(models.Model):
    
    profile_picture = models.ImageField(upload_to="patient_profile/", default='default_profile_pic.jpg', null=True, blank=True)
    address_1 = models.CharField(max_length=250, null=True, blank=True)
    address_2 = models.CharField(max_length=250, null=True, blank=True)
    city = models.CharField(max_length=250, null=True, blank=True)
    country = models.CharField(max_length=250, null=True, blank=True)
    patient = models.OneToOneField(Patient, on_delete=models.CASCADE, related_name='patient_profile')

    def __str__(self):
        return f"Profile - {self.city or 'No City'}"


class Day(models.Model):
    """
    Model for days of the week
    """
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class AppointmentSlot(models.Model):
    """
    Appointment slot model for doctor availability
    """


    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='appointment_slots')
    room = models.IntegerField(default=101)
    day = models.OneToOneField(Day, on_delete=models.CASCADE)
    start_time = models.TimeField()
    end_time = models.TimeField()
    date = models.DateField()
    decider1 = models.TimeField(default=time(0, 0))
    decider2 = models.TimeField(default=time(0, 10))
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.doctor.user.get_full_name()}: {self.day}({self.start_time} - {self.end_time})"

class Appointment(models.Model):
    """
    Appointment model to manage patient-doctor consultations
    """
    APPOINTMENT_STATUS_CHOICES = (
        ('booked', 'Booked'),
        ('confirmed', 'Confirmed'),
        ('completed', 'Completed'),
        ('canceled', 'Canceled')
    )

    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='appointments')
    #doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='appointments')
    slot = models.ForeignKey(AppointmentSlot, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=APPOINTMENT_STATUS_CHOICES, default='booked')
    consultation_fee = models.DecimalField(max_digits=10, decimal_places=2)
    start_time = models.TimeField()
    end_time = models.TimeField()
    payment_status = models.BooleanField(default=False)
    payment_timestamp = models.DateTimeField(null=True, blank=True)
    transaction_id = models.CharField(max_length=255, unique=True, blank=True, null=True)
    
    def generate_transaction_id(self):
        if not self.transaction_id:
            self.transaction_id = f"TX-{uuid.uuid4().hex}"
            while Appointment.objects.filter(transaction_id=self.transaction_id).exists():
                self.transaction_id = f"TX-{uuid.uuid4().hex}"
            self.save()
        return self.transaction_id

    def __str__(self):
        return f"{self.patient.user.get_full_name()} with {self.slot.doctor.user.get_full_name()}"

class Prescription(models.Model):
    """
    Prescription model for medical records
    """
    appointment = models.OneToOneField(Appointment, on_delete=models.CASCADE, related_name='prescription')
    prescription_text = models.TextField()
    additional_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    email_sent = models.BooleanField(default=False)

    def __str__(self):
        return f"Prescription for {self.appointment.patient.user.get_full_name()}"

class DiagnosticReport(models.Model):
    """
    Diagnostic report upload model for patients
    """
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='diagnostic_reports')
    report_file = models.FileField(upload_to='diagnostic_reports/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"Report for {self.patient.user.get_full_name()} - {self.uploaded_at}"

class Review(models.Model):
    """
    Review model for patient feedback on doctors
    """
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='reviews')
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review by {self.patient.user.get_full_name()} for {self.doctor.user.get_full_name()}"
