# Hand-authored (the container has no bind mount, so makemigrations is not run
# in-image; the schema is small and stable). Mirrors labs/post_11_brute_force.
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Secret',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('body', models.TextField()),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='secrets', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'sessionfixation_secret',
            },
        ),
    ]
