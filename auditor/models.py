from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class User(AbstractUser):
    # Other custom fields (if any)
    
    groups = models.ManyToManyField(
        Group,
        related_name="auditor_users",  # Change related_name to avoid conflict
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="auditor_user_permissions",  # Change related_name to avoid conflict
        blank=True
    )
