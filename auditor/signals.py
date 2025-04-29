from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

# Disconnect Django’s default update_last_login
user_logged_in.receivers = []
