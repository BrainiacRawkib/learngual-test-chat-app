import json

from django.core.management.base import BaseCommand

from core import settings as core_settings
from apis.clients.models import Client


class Command(BaseCommand):

    def handle(self, *args, **options):
        """
        execute command
        """
        self._create_client()
        self.stdout.write(self.style.SUCCESS(
            '==================== Operation Complete! ===================='
        ))

    def _create_client(self):
        """
        seed client on start up
        """
        client_json = core_settings.BASE_DIR / 'app_clients/test_data.json'

        with open(f'{client_json}', 'r') as f:
            data = json.load(f)
            for datum in data:
                if Client.get_by_id(datum['client_id']):
                    # if client exists, do nothing
                    self.stdout.write(self.style.ERROR(
                        f"{datum['client_id']} already exists!"
                    ))
                    pass
                else:
                    # if client does not exist, create new client
                    self.stdout.write(self.style.SUCCESS(
                        f"Successfully created {datum['client_id']} client!"
                    ))
                    Client.create(datum)
