from django.apps import AppConfig


class LabsConfig(AppConfig):
    """Container app for cross-lab tooling. Ships no models of its own.

    It exists so project-wide management commands (currently `seed_labs`) have
    a home that does not belong to any single lab.
    """

    name = "labs"
    label = "labs"
    verbose_name = "Labs (shared tooling)"
