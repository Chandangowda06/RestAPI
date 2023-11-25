# Generated by Django 4.2.7 on 2023-11-23 04:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_app', '0012_alter_events_author'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='author',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='author', to='user_app.profile'),
        ),
    ]