from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
import random


# Custom user model extending the AbstractUser
class OTAUser(AbstractUser):
    is_deleted = models.BooleanField(default=False)  # Soft delete flag
    ota_active = models.BooleanField(default=False)  # User is inactive until OTP verification

# OTP model for managing one-time passwords
class OTP(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="otps")
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        """Check if the OTP is expired."""
        return timezone.now() > self.expires_at

    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP."""
        return str(random.randint(100000, 999999))  # Generate a random OTP
