# Generated by Django 4.1.7 on 2023-04-07 23:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0016_rename_protocol1_file_arp_rename_protocol2_file_icmp_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='Sourcemac',
            field=models.CharField(max_length=256, null=True),
        ),
        migrations.AddField(
            model_name='file',
            name='destinationmac',
            field=models.CharField(max_length=256, null=True),
        ),
        migrations.AddField(
            model_name='file',
            name='index',
            field=models.CharField(max_length=256, null=True),
        ),
    ]
