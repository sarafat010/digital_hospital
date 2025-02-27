from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from .forms import *
from .models import *
from django.db.models import Q, Avg, Count
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import BadHeaderError
from django.http import HttpResponse
from django.urls import reverse
from django.http import HttpResponseBadRequest
import requests
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from sslcommerz_lib import SSLCOMMERZ
from decimal import Decimal
import json
import hashlib
import random
from django.contrib.auth.hashers import make_password
from datetime import datetime, timedelta, time
from .decorators import admin_required, doctor_required, patient_required
from django.contrib.auth.decorators import login_required, user_passes_test

# Check for user type
def is_admin(user):
    return user.user_type == 'admin'

def is_doctor(user):
    return user.user_type == 'doctor'

def is_patient(user):
    return user.user_type == 'patient'

def register_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Registration successful!')
            return redirect('home')
    else:
        form = UserRegistrationForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful!')
                #return redirect('home')
                return dashboard_view(request)

            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = UserLoginForm()
    return render(request, 'login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
def update_password(request):
    if request.user.is_authenticated:
        current_user = request.user
        if request.method == "POST":
            form = ChangePasswordForm(current_user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Your Password Has been Updated..")
                login(request, current_user)
                return redirect("home")
            else:
                for error in list(form.errors.values()):
                    messages.error(request, error)
                    return redirect("home")
        else:
            form = ChangePasswordForm(current_user)
        return render(request, "update_password.html", {"form":form})
    else:
        messages.success(request, "You must be logged in to view that page...")
        return redirect("home")



@login_required
def dashboard_view(request):
    
    if request.user.user_type == 'admin':       
        return redirect('admin_dashboard')
    elif request.user.user_type == 'doctor':
        return redirect('doctor_dashboard')
    else:
        return redirect('patient_dashboard')

@admin_required
def admin_dashboard(request):
    full_name = request.user.get_full_name()
    return render(request, 'admin_dashboard.html', {"full_name":full_name})

@doctor_required
def doctor_dashboard(request):
    doctor = Doctor.objects.get(user=request.user)
    appointments = Appointment.objects.filter(
        slot__doctor=doctor,
        slot__start_time__gte=timezone.now().replace(hour=0, minute=0, second=0)
        ).order_by('slot__date','slot__start_time')
    
    rating = Review.objects.filter(doctor=doctor).aggregate(avg_rating=Avg("rating"))["avg_rating"] or 0
    no_of_patient = Appointment.objects.filter(slot__doctor=doctor, slot__date=datetime.today()).aggregate(total_patients=Count('patient', distinct=True))['total_patients']

    
    return render(request, 'doctor_dashboard.html', {"appointments":appointments, "doctor":doctor, "rating":rating, "total_patients":no_of_patient}) 

@patient_required
def patient_dashboard(request):
    patient = Patient.objects.get(user=request.user)
    appointments = Appointment.objects.filter(
        patient=patient,
        slot__start_time__gte=timezone.now().replace(hour=0, minute=0, second=0)
        ).order_by('slot__date', 'slot__start_time')
    
    prescriptions = []

    for appointment in appointments:
        prescriptions.append(Prescription.objects.filter(appointment=appointment)) 

    print(prescriptions)
    
    return render(request, 'patient_dashboard.html', {"appointments":appointments, "prescriptions":prescriptions, "patient_id":patient.id, "user_id":patient.user.id, "date":datetime.today()})


def home(request):
    return render(request, "home.html")


@login_required
def create_appointment_slot(request):
    if request.method == 'POST':
        form = AppointmentSlotForm(request.POST)
        if form.is_valid():
            slot = form.save(commit=False)
            date = get_next_date(slot.day.name) 
            slot.date = date
            slot.save()
            return redirect('appointment_slot_list')  # Redirect to a list view or another page
    else:
        form = AppointmentSlotForm()
    return render(request, 'appointment_slot_form.html', {'form': form})

def get_next_date(day_name):
    day_map = {
        'monday': 0,
        'tuesday': 1,
        'wednesday': 2,
        'thursday': 3,
        'friday': 4,
        'saturday': 5,
        'sunday': 6
    }
    day_name = day_name.lower()
    today = datetime.now()
    current_day = today.weekday()
    target_day = day_map.get(day_name)

    if target_day is None:
        raise ValueError("Invalid day name. Please provide a valid day (e.g., 'Wednesday').")

    days_until_target = (target_day - current_day + 7) % 7

    if days_until_target == 0:
        days_until_target = 7

    next_date = today + timedelta(days=days_until_target)


    return next_date

@login_required
def update_appointment_slot(request, pk):
    appointment_slot = AppointmentSlot.objects.get(pk=pk)
    if request.method == 'POST':
        form = AppointmentSlotForm(request.POST, instance=appointment_slot)
        if form.is_valid():
            form.save()
            return redirect('appointment_slot_list')  # Redirect to a list view or another page
    else:
        form = AppointmentSlotForm(instance=appointment_slot)
    return render(request, 'appointment_slot_form.html', {'form': form})

@login_required
def delete_appointment_slot(request, pk):
    if not request.user.is_authenticated or not (request.user.is_superuser or request.user.user_type == 'doctor'):
        messages.error(request, "You do not have permission to delete this appointment slot.")
        return redirect('home')  

    appointment_slot = get_object_or_404(AppointmentSlot, pk=pk)

    if request.user.user_type == 'doctor' and appointment_slot.doctor.user != request.user:
        messages.error(request, "You can only delete your own appointment slots.")
        return redirect('appointment_slot_list')  

    appointment_slot.delete()
    messages.success(request, "Appointment slot deleted successfully.")

    return redirect('appointment_slot_list')

@login_required
def appointment_slot_list(request):
    slot = AppointmentSlot.objects.all()

    return render(request, "appointment_slot_list.html", {"slot_list":slot})

@login_required
def doctor_list(request):
    doctors = Doctor.objects.all()
    specializations = Specialization.objects.all()


    return render(request, "doctor_list.html", {"doctors":doctors, "specializations":specializations})

@login_required
def search_doctor(request):
    if request.method == "POST":
        searched = request.POST.get("searched")
        
        doctors = Doctor.objects.filter(Q(user__first_name__icontains=searched) | Q(user__last_name__icontains=searched) | Q(specialization__name__icontains=searched) | Q(specialization__description__icontains=searched)).distinct()
        if doctors:
            return render(request, "search_doctor.html", {"doctors":doctors})
        else:
            return render(request, "search_doctor.html", {})
    else:
        return render(request, "search_doctor.html", {})


""" @login_required
@patient_required
def create_appointment(request, doctor_id):
    user = request.user
    slots = AppointmentSlot.objects.filter(doctor__id=doctor_id)

    for slot in slots:
        date = get_next_date(slot.day.name)
        slot.date = date
        slot.save()


    if request.method == 'POST':
        #form = AppointmentForm(request.POST)
        form = AppointmentForm()
        slot_id = request.POST.get("slot_id")
        slot = get_object_or_404(AppointmentSlot, id=slot_id)
        if form.is_valid():
            patient = Patient.objects.get(user=user)
            appointment = form.save(commit=False)
            slot = AppointmentSlot.objects.get(id=appointment.slot.id)
            appointment.patient = patient
            appointment.consultation_fee = slot.doctor.consultation_fee
            start_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider1.hour * 60 + slot.decider1.minute)).time()
            end_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider2.hour * 60 + slot.decider2.minute)).time()
            
            
            decider1_datetime = datetime.combine(slot.date, slot.decider1) + timedelta(minutes=10)
            decider2_datetime = datetime.combine(slot.date, slot.decider2) + timedelta(minutes=10)

            if end_time > slot.end_time:
                slot.decider1 = time(0, 0) 
                slot.decider2 = time(0, 10)  
                slot.date += timedelta(days=7)
                start_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider1.hour * 60 + slot.decider1.minute)).time()
                end_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider2.hour * 60 + slot.decider2.minute)).time()
            
            else:
                slot.decider1 = decider1_datetime.time()
                slot.decider2 = decider2_datetime.time()

            appointment.start_time = start_time
            appointment.end_time = end_time
 
            appointment.save()
            slot.save()
            return redirect('appointment_list', pk=user.id)  
            #return redirect('initiate_payment', appointment_id=appointment.id)
    else:
        form = AppointmentForm() #initial={'patient': user.patient_profile}
    return render(request, 'appointment_form.html', {'form': form, 'slots':slots}) """


@login_required
@patient_required
def create_appointment(request, doctor_id):
    user = request.user
    slots = AppointmentSlot.objects.filter(doctor__id=doctor_id)

    for slot in slots:
        date = get_next_date(slot.day.name)
        slot.date = date
        slot.save()


    if request.method == 'POST':
        slot_id = request.POST.get("slot_id")
        slot = get_object_or_404(AppointmentSlot, id=slot_id)
        
        patient = Patient.objects.get(user=user)
        start_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider1.hour * 60 + slot.decider1.minute)).time()
        end_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider2.hour * 60 + slot.decider2.minute)).time()
        
        
        decider1_datetime = datetime.combine(slot.date, slot.decider1) + timedelta(minutes=10)
        decider2_datetime = datetime.combine(slot.date, slot.decider2) + timedelta(minutes=10)

        if end_time > slot.end_time:
            slot.decider1 = time(0, 0) 
            slot.decider2 = time(0, 10)  
            slot.date += timedelta(days=7)
            start_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider1.hour * 60 + slot.decider1.minute)).time()
            end_time = (datetime.combine(slot.date, slot.start_time) + timedelta(minutes=slot.decider2.hour * 60 + slot.decider2.minute)).time()
        
        else:
            slot.decider1 = decider1_datetime.time()
            slot.decider2 = decider2_datetime.time()

        appointment = Appointment.objects.create(
            patient = patient,
            slot = slot,
            consultation_fee = slot.doctor.consultation_fee,
            start_time = start_time,
            end_time = end_time
        )

        appointment.save()
        slot.save()
        return redirect('appointment_list', pk=user.id)  
        
    else:
        form = AppointmentForm() 
    return render(request, 'appointment_form.html', {'form': form, 'slots':slots})


@login_required
@doctor_required
def update_appointment(request, pk):
    user = request.user
    appointment = Appointment.objects.get(pk=pk)
    if request.method == 'POST':
        status = request.POST.get("status")
        appointment.status = status
        if status == "completed":
            patient = get_object_or_404(Patient, id=appointment.patient.id)
            patient.last_checkup = datetime.today()
            patient.save()
        appointment.save()
        if user.user_type == 'doctor':
            return redirect('doctor_dashboard')
        return redirect('appointment_list', pk=user.id)  # Redirect to a list view or another page
    else:
        form = AppointmentForm(instance=appointment)
    return render(request, 'appointment_update_form.html', {'pk':pk})


def appointment_details(request, appoint_id):
    appointment = get_object_or_404(Appointment, id=appoint_id)
    return render(request, "appointment_details.html", {"appointment":appointment})

@login_required
def appointment_list(request, pk):
    # Fetch the user type and ensure the user is authorized
    user = request.user
    if not user.is_authenticated:
        return render(request, "error.html", {"message": "You must be logged in to view appointments."})

    # Check if the logged-in user is the patient or doctor associated with the appointments
    if user.user_type == 'patient':
        patient = get_object_or_404(Patient, user=user)
        appointments = Appointment.objects.filter(patient=patient).order_by("-slot__date")
    elif user.user_type == 'doctor':
        doctor = get_object_or_404(Doctor, user=user)
        appointments = Appointment.objects.filter(slot__doctor=doctor).order_by("-slot__date")
    else:
        # If the user is not a patient or doctor, return an error
        return render(request, "error.html", {"message": "You do not have permission to view appointments."})

    return render(request, "appointment_list.html", {"appointments": appointments})

@doctor_required
def today_appointments(request, doctor_id):
    try:
        appointments = Appointment.objects.filter(slot__doctor__id=doctor_id, slot__date=datetime.today())
    
    except:
        messages.error(request, "There is no appointments today ")
        return redirect("doctor_dashboard")
    
    return render(request, "today_appointments.html", {"appointments":appointments})


@doctor_required
def create_prescription(request, appointment_id):
    appointment = get_object_or_404(Appointment, id=appointment_id)

    if request.method == 'POST':
        form = PrescriptionForm(request.POST)
        if form.is_valid():
            prescription = form.save(commit=False)
            prescription.appointment = appointment
            prescription.save()
            if not prescription.email_sent:
                send_email_to_patient(request, appointment.patient.user.email, prescription)
                prescription.email_sent = True
            return redirect("doctor_dashboard")
            #return redirect('prescription_detail', pk=prescription.pk)
    else:
        form = PrescriptionForm()
    return render(request, 'prescription_form.html', {'form': form})

@doctor_required
def update_prescription(request, pk):
    prescription = get_object_or_404(Prescription, pk=pk)
    if request.method == 'POST':
        form = PrescriptionForm(request.POST, instance=prescription)
        if form.is_valid():
            form.save()
            send_email_to_patient(request,prescription.appointment.patient.user.email, prescription)
            #return redirect('prescription_detail', pk=prescription.pk)
            return redirect("doctor_dashboard")
    else:
        form = PrescriptionForm(instance=prescription)
    return render(request, 'prescription_form.html', {'form': form})

@login_required
def prescription_detail(request, apoint_id):
    try:
        prescription = get_object_or_404(Prescription, appointment__id=apoint_id)
    except:
        messages.info(request, "Prescription doesn't exist... please create first")
        return create_prescription(request, apoint_id)

    return render(request, 'prescription_detail.html', {'prescription': prescription, "apointment_id":apoint_id})



def send_email_to_patient(request, patient, prescription):
    subject = "Doctor Prescription"
    message = prescription.prescription_text + prescription.additional_notes 
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [patient]

    try:
        send_mail(subject, message, from_email, recipient_list)
        messages.success(request, "Email sent successfully!")
    except BadHeaderError:
        return HttpResponse("Invalid header found.")
    except Exception as e:
        # Log the error (optional) and return a failure message
        print(f"Error sending email: {e}")
        return HttpResponse("Failed to send email.")
    
    return HttpResponse("Email sent successfully.")

@patient_required
def upload_report(request):
    if request.method == 'POST':
        form = DiagnosticReportForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                patient = Patient.objects.get(user=request.user)
            except Patient.DoesNotExist:
                
                return HttpResponse("Patient profile not found.", status=404)
            report = form.save(commit=False)
            report.patient = patient  # Set the patient based on the logged-in user
            report.save()
            print("Form is valid")
            return redirect('patient_dashboard')
    else:
        form = DiagnosticReportForm()

    return render(request, 'report_form.html', {'form': form})

@patient_required
def edit_report(request, report_id):
    report = get_object_or_404(DiagnosticReport, id=report_id)
    
    if request.method == 'POST':
        form = DiagnosticReportForm(request.POST, request.FILES, instance=report)
        if form.is_valid():
            form.save()  
            return redirect('report_view', patient_id=report.patient.user.id)  
    else:
        # Populate the form with the existing report instance
        form = DiagnosticReportForm(instance=report)
    
    return render(request, 'report_form.html', {'form': form, 'report': report})


@login_required
def report_view(request, patient_id):

    print(f'patient_id: {patient_id}')
    
    reports = DiagnosticReport.objects.filter(patient__user__id = patient_id)
    
    return render(request, 'report_detail.html', {'reports': reports})

@login_required
def appointment_prescription_history(request, pk):
    patient = Patient.objects.get(id=pk)
    appointments = Appointment.objects.filter(
        patient=patient
        ).order_by('slot__start_time')
    
    prescriptions = []

    for appointment in appointments:
        prescriptions.append(Prescription.objects.filter(appointment=appointment)) 

    print(prescriptions)
    
    return render(request, 'appointment_prescription_history.html', {"appointments":appointments, "prescriptions":prescriptions})


@login_required
def create_review(request, doctor_id):
    if request.method == "POST":
        form = ReviewForm(request.POST)
        if form.is_valid():
            patient = Patient.objects.get(user=request.user)
            doctor = Doctor.objects.get(id=doctor_id)

            review = form.save(commit=False)
            review.patient = patient
            review.doctor = doctor
            review.save()
            messages.success(request, "Review created successfully")
            return redirect("home")
    
    else:
        form = ReviewForm()

    return render(request, "review_form.html", {"form":form})

@login_required
def show_review(request, doctor_id):
    reviews = Review.objects.filter(doctor__id=doctor_id)

    return render(request, "review_list.html", {"reviews":reviews})





config = {
    'store_id': 'mycom679f4c8635e9f',
    'store_pass': 'mycom679f4c8635e9f@ssl',
    'issandbox': True  # Set to False for production
}

sslcz = SSLCOMMERZ(config=config)



def initiate_payment(request, appointment_id):
    try:
        appointment = Appointment.objects.get(id=appointment_id)
        
        if appointment.payment_status:
            messages.warning(request, 'Payment already completed!')
            return redirect('appointment_detail', appointment_id=appointment_id)

        transaction_id = appointment.generate_transaction_id()
       
        # Initialize SSLCommerz
        

        status_url = f"{settings.SSLCOMMERZ_SETTINGS['redirect_url']}/payment/"
        
        # Set payment data
        payment_data = {
            'total_amount': float(appointment.consultation_fee),  # Convert Decimal to float
            'currency': 'BDT',
            'tran_id': transaction_id,
            'success_url': f"{status_url}success/",
            'fail_url': f"{status_url}failed/",
            'cancel_url': f"{status_url}canceled/",
            'emi_option': 0,
            'cus_name': appointment.patient.user.get_full_name(),
            'cus_email': appointment.patient.user.email,
            'cus_phone': appointment.patient.user.phone_number or 'Not Provided',
            'cus_add1': appointment.patient.patient_profile.address_1 or 'Not Provided',
            'cus_add2': appointment.patient.patient_profile.address_2 or 'Not Provided',
            'cus_city': appointment.patient.patient_profile.city or 'Not Provided',
            'cus_country': appointment.patient.patient_profile.country or 'Bangladesh',
            'shipping_method': 'NO',
            'product_name': 'Doctor Appointment',
            'product_category': 'Healthcare',
            'product_profile': 'service',
            'value_a': appointment_id,  # Additional field for appointment ID
        }

        # Initiate payment
        response = sslcz.createSession(payment_data)

        if response['status'] == 'SUCCESS':
            return redirect(response['GatewayPageURL'])
        
        messages.error(request, 'Failed to initialize payment')
        return redirect('appointment_list', pk=appointment_id)

    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')
        return redirect('appointment_list', pk=appointment_id)





@csrf_exempt
def payment_success(request):
    if request.method == 'POST':
        payment_data = request.POST.dict()
        print("Payment Data:", payment_data)
        
        # Verify mandatory fields exist
        required_fields = ['val_id', 'verify_sign_sha2', 'tran_id', 'value_a']
        if not all(payment_data.get(field) for field in required_fields):
            messages.error(request, 'Invalid payment response')
            return redirect('home')

        # Get credentials from settings
        store_id = settings.SSLCOMMERZ_SETTINGS['store_id']
        store_pass = settings.SSLCOMMERZ_SETTINGS['store_pass']
        
        # Extract values from response
        val_id = payment_data['val_id']
        received_signature = payment_data['verify_sign_sha2']
        transaction_id = payment_data['tran_id']
        appointment_id = payment_data['value_a']

        # 1. Validate Transaction ID matches appointment
        try:
            appointment = Appointment.objects.get(
                id=appointment_id,
                transaction_id=transaction_id
            )
        except Appointment.DoesNotExist:
            messages.error(request, 'Invalid appointment or transaction ID')
            return redirect('home')

        # 2. Validate SSLCommerz Signature (SHA-2)
        signature_data = {
            'val_id': val_id,
            'store_id': store_id,
            'store_passwd': store_pass,
            'format': 'json'
        }
        
        # Verify through SSLCommerz API
        verify_url = "https://sandbox.sslcommerz.com/validator/api/merchantTransIDvalidationAPI.php"
        response = requests.get(verify_url, params=signature_data)
        
        if response.status_code == 200:
            verification = response.json()

            print("Hello")
            if verification['status'] == 'VALID' and verification['tran_id'] == transaction_id:
                # Update appointment status
                appointment.payment_status = True
                appointment.payment_timestamp = timezone.now()
                appointment.status = 'confirmed'
                appointment.save()
                messages.success(request, 'Payment verified successfully!')
                appointment_confirmation_email(request, appointment)
                return redirect('appointment_list', pk=appointment_id)
        
        messages.error(request, 'Payment verification failed')
        return redirect('home')

    messages.error(request, 'Invalid request method')
    return redirect('home')


@csrf_exempt
def payment_failed(request):
    messages.error(request, 'Payment failed. Please try again.')
    return redirect('home')

@csrf_exempt
def payment_canceled(request):
    messages.warning(request, 'Payment was canceled.')
    return redirect('home')

@csrf_exempt
def payment_ipn(request):
    return HttpResponse("IPN")



def appointment_confirmation_email(request, appointment):
    subject = "Doctor Appointment confirmation"
    #message =  f"Appointment for {appointment.patient.user.__get_full_name}\n Doctor: {appointment.doctor.user.__get_full_name}\n Room: {102}\n Time: {appointment.slot.start_time} to {appointment.slot.end_time}"
    message = f"""
        Dear {appointment.patient.user.get_full_name()},

        Your appointment has been confirmed with the following details:

        Doctor: {appointment.slot.doctor.user.get_full_name()}
        Room: {appointment.slot.room} 
        Meeting ID: {appointment.slot.doctor.user.username} 
        Date: {appointment.slot.date.strftime('%B %d, %Y')}, {appointment.slot.day}
        Time: {appointment.start_time.strftime('%I:%M %p')} to {appointment.end_time.strftime('%I:%M %p')}

        Please arrive 5 minutes before your scheduled time.
        Thank you for choosing our healthcare services.

        PH HealthCare
        """
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [appointment.patient.user.email]

    try:
        send_mail(subject, message, from_email, recipient_list)
        messages.success(request, "Email sent successfully!")
    except BadHeaderError:
        return HttpResponse("Invalid header found.")
    except Exception as e:
        # Log the error (optional) and return a failure message
        print(f"Error sending email: {e}")
        return HttpResponse("Failed to send email.")
    
    return HttpResponse("Email sent successfully.")



def reset_password(request):
    if request.method == "POST":
        email = request.POST.get("email")

        OTP = random.randint(1000, 9999)
        print(f"otp: {OTP}, email: {email}")

        subject = "Password reset verification otp"
        message = f"your OTP is {OTP}"
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email,]

        try:
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, "Email sent successfully!")
            return redirect("otp_view", OTP, email)
        except BadHeaderError:
            return HttpResponse("Invalid header found.")
        except Exception as e:
            # Log the error (optional) and return a failure message
            print(f"Error sending email: {e}")
            return HttpResponse("Failed to send email.")
        


    return render(request, "reset_password_form.html")



def otp_view(request, otp, email):
    if request.method == "POST":
        OTP = int(request.POST.get("otp"))
        print(f"otp : {OTP}")
        if OTP == otp:
            return redirect("set_password", email)
            


    return render(request, "otp_form.html", {"otp":otp, "email":email})




def set_password(request, email):
    if request.method == "POST":
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        user = User.objects.get(email=email)
        if new_password == confirm_password:
            # Hash the new password and save it
            user.password = make_password(new_password)
            user.save()

            # Authenticate and log the user in
            user = authenticate(username=user.username, password=new_password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Password reset successful!')
                return dashboard_view(request) 
    
    return render(request, "set_password.html", {"email":email})



@login_required
def patient_profile(request, user_id):
    user = request.user
    if user.is_authenticated:
        profile = PatientProfile.objects.get(patient__user__id=user_id)
    else:
        messages.error(request, "The user is not authenticate!")
        return redirect("home")
    
    return render(request, "patient_profile.html", {"profile":profile})

@login_required
@patient_required
def update_patient_profile(request, user_id):
    patient = get_object_or_404(Patient, user__id=user_id)
    patient_profile = get_object_or_404(PatientProfile, patient= patient)

    user_form = UserForm(instance=request.user)
    patient_form = PatientForm(instance=patient)
    profile_form = PatientProfileForm(instance=patient_profile)
    if request.method == "POST":
        user_form = UserForm(request.POST, instance=request.user)
        patient_form = PatientForm(request.POST, instance=patient)
        profile_form = PatientProfileForm(request.POST, request.FILES, instance=patient_profile)

        if all([user_form.is_valid(), patient_form.is_valid(), profile_form.is_valid()]):
            user_form.save()
            patient_form.save()
            profile_form.save()

            return redirect("patient_profile", user_id)
            
    return render(request, "update_patient_profile.html", {"user_form":user_form, "patient_form":patient_form, "profile_form":profile_form, "user_id":user_id})



@login_required
@doctor_required
def update_doctor_profile(request, doctor_id):
    doctor = get_object_or_404(Doctor, id=doctor_id)
    if request.method == "POST":
        form = DoctorProfileForm(request.POST, request.FILES, instance=doctor)
        if form.is_valid():
            form.save()
            return redirect("doctor_dashboard")
    else:
        form = DoctorProfileForm(instance=doctor)
    return render(request, "update_doctor_profile.html", {"form":form, "doctor":doctor})


@login_required
def doctor_profile(request, user_id):
    doctor = get_object_or_404(Doctor, user__id=user_id)
    total_patient_treated = Appointment.objects.filter(slot__doctor=doctor).aggregate(total_patients=Count('patient', distinct=True))['total_patients']


    return render(request, "doctor_profile.html", {"doctor":doctor, "total_patient_treated":total_patient_treated})

@login_required
def doctor_details(request, doctor_id):
    doctor = get_object_or_404(Doctor, id=doctor_id)

    rating = Review.objects.filter(doctor=doctor).aggregate(avg_rating=Avg("rating"))["avg_rating"] or 0
    slots = AppointmentSlot.objects.filter(doctor=doctor)

    return render(request, "doctor_details.html", {"doctor":doctor, "rating":rating, "slots":slots})



@login_required
def video_chat(request, room_id):
    return render(request, 'video_chat.html', {'room_id': room_id})

@login_required
def doctor_category(request, cat_name):
    cat_name = cat_name.replace("-", " ")
    specialization = Specialization.objects.get(name=cat_name)
    doctors = Doctor.objects.filter(specialization = specialization)
    
    return render(request, "doctor_category.html", {"doctors":doctors, "cat_name":cat_name})

@login_required
def about(request):
    return render(request, "about.html", {})
        
