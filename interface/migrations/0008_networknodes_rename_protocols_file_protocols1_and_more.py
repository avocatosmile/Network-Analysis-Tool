# Generated by Django 4.1.7 on 2023-04-01 17:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0007_interfaceuser'),
    ]

    operations = [
        migrations.CreateModel(
            name='Networknodes',
            fields=[
                ('FileId', models.AutoField(primary_key=True, serialize=False)),
                ('Packetsource', models.CharField(max_length=256, null=True)),
                ('Packetdestination', models.CharField(max_length=256, null=True)),
            ],
        ),
        migrations.RenameField(
            model_name='file',
            old_name='protocols',
            new_name='protocols1',
        ),
        migrations.AddField(
            model_name='file',
            name='protocols2',
            field=models.CharField(max_length=256, null=True),
        ),
    ]