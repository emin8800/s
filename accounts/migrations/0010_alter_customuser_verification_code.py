# Generated by Django 5.1 on 2024-10-28 19:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_customuser_is_2fa_enabled'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='verification_code',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
    ]