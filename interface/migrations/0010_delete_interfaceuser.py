# Generated by Django 4.1.7 on 2023-04-01 17:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0009_rename_protocols1_file_protocals1_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='interfaceUser',
        ),
    ]