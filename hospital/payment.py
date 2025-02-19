# hospital/payment.py
from django.conf import settings
import requests
from zeep import Client
from .models import *

class SSLCommerz:
    @staticmethod
    def create_session(appointment):
        try:
            patient = Patient.objects.get(id=appointment.patient.id)
            patient_profile = PatientProfile.objects.get(patient=patient)
            payload = {
                'store_id': settings.SSLCOMMERZ_STORE_ID,
                'store_passwd': settings.SSLCOMMERZ_STORE_PASSWORD,
                'total_amount': f"{appointment.consultation_fee:.2f}",
                'currency': 'BDT',
                'tran_id': appointment.generate_transaction_id(),
                'success_url': f"{settings.BASE_URL}/payment-success/",
                'fail_url': f"{settings.BASE_URL}/payment-fail/",
                'cancel_url': f"{settings.BASE_URL}/payment-cancel/",
                'cus_name': patient.user.get_full_name(),
                'cus_email': patient.user.email,
                'cus_phone': patient.user.phone_number,
                'cus_add1': patient_profile.address_1,
                'cus_city': patient_profile.city,
                'cus_country': patient_profile.country,
                'shipping_method': 'NO',
                'product_name': 'Medical Consultation',
                'product_category': 'Healthcare',
                'product_profile': 'general',
            }

            
            
            response = requests.post(settings.SSLCOMMERZ_SESSION_API, data=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error creating payment session: {e}")
            return {'status': 'FAILED', 'error': str(e)}

    @staticmethod
    def validate_transaction(val_id):
        client = Client(settings.SSLCOMMERZ_VALIDATION_API)
        return client.service.validateTransaction(
            val_id=val_id,
            store_id=settings.SSLCOMMERZ_STORE_ID,
            store_passwd=settings.SSLCOMMERZ_STORE_PASSWORD,
            v='1',
            format='json'
        )