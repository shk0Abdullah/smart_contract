# Generated by Django 3.1.12 on 2025-04-18 01:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auditor', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=150, unique=True),
        ),
    ]
