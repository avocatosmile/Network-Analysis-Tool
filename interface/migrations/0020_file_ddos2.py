# Generated by Django 4.1.7 on 2023-04-08 23:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interface', '0019_rename_index_file_sourceiparp_file_sourcemacarp_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='DDos2',
            field=models.CharField(max_length=256, null=True),
        ),
    ]
