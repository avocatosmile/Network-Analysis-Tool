# Generated by Django 4.1.7 on 2023-04-08 23:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0021_file2'),
    ]

    operations = [
        migrations.DeleteModel(
            name='file2',
        ),
        migrations.RemoveField(
            model_name='file',
            name='DDos2',
        ),
    ]
