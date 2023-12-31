# Generated by Django 4.2.7 on 2023-11-24 04:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_app', '0018_alter_events_description'),
    ]

    operations = [
        migrations.CreateModel(
            name='LeaveData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total_leaves', models.IntegerField(default=12)),
                ('leaves_taken', models.IntegerField(default=0)),
                ('staff_profile', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='staff_profile', to='user_app.profile')),
            ],
        ),
        migrations.CreateModel(
            name='LeaveApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_id', models.CharField(max_length=20)),
                ('leave_type', models.CharField(choices=[('Casual Leave', 'Casual Leave'), ('Half-day leave', 'Half-day leave'), ('One-day leave', 'One-day leave'), ('Earned/Vacation/Privilege Leave', 'Earned/Vacation/Privilege Leave'), ('Sick Leave/Medical Leave', 'Sick Leave/Medical Leave'), ('Maternity Leave', 'Maternity Leave'), ('Paternity leaves', 'Paternity leaves'), ('Sabbatical Leave', 'Sabbatical Leave'), ('Bereavement leave', 'Bereavement leave'), ('Compensatory leave', 'Compensatory leave'), ('Compassionate leave', 'Compassionate leave')], max_length=100)),
                ('leave_reason', models.CharField(max_length=500)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('approval_status', models.CharField(choices=[('Pending', 'Pending Approval'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Pending', max_length=20)),
                ('approved_hod', models.BooleanField(default=False)),
                ('approved_principal', models.BooleanField(default=False)),
                ('approved_director', models.BooleanField(default=False)),
                ('approved_ceo', models.BooleanField(default=False)),
                ('letter', models.FileField(blank=True, default=None, upload_to='')),
                ('submission_timestamp', models.DateTimeField(auto_now_add=True)),
                ('hod_approval_timestamp', models.DateTimeField(blank=True, null=True)),
                ('principal_approval_timestamp', models.DateTimeField(blank=True, null=True)),
                ('director_approval_timestamp', models.DateTimeField(blank=True, null=True)),
                ('ceo_approval_timestamp', models.DateTimeField(blank=True, null=True)),
                ('alternative_staff', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='alternative_staff', to='user_app.profile')),
                ('applicant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='applicant', to='user_app.profile')),
            ],
        ),
    ]
