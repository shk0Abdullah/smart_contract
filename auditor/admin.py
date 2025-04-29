from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, SlitherReport, Buy

# Register your models here.
admin.site.register(User, UserAdmin)
admin.site.register(SlitherReport )
admin.site.register(Buy)

