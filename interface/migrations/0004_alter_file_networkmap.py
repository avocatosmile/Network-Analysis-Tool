# Generated by Django 4.1.7 on 2023-03-29 07:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0003_alter_file_file'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='Networkmap',
            field=models.ImageField(upload_to='images'),
        ),
    ]
