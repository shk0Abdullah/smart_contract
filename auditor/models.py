from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from djongo.models import ObjectIdField
from django.utils import timezone
from bson import ObjectId
from django.conf import settings

class User(AbstractUser):
    id = ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    username = models.CharField(max_length=150, unique=True)
    def __str__(self):
        return self.username
class Contact(models.Model):
    email = models.EmailField()
    message = models.TextField(max_length=255)
    def __str__(self):
        return self.email
class SlitherReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='slither_reports')
    report_name = models.CharField(max_length=255)  
    report_data = models.TextField()  
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='completed')  # Add status field
    
    def __str__(self):
        return f"Slither Report for {self.user.username} on {self.created_at}"
class Buy(models.Model):
    wallet_address = models.CharField(max_length=42)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='buys')
    to_address = models.CharField(max_length=42)
    transaction_hash = models.CharField(max_length=66, unique=True)
    block_number = models.PositiveBigIntegerField()
    event_name = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=40, decimal_places=8)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Buy event {self.event_name} by {self.wallet_address} in block {self.block_number}"