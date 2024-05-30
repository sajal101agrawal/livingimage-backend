# home/management/commands/advance_test_clock.py

from django.core.management.base import BaseCommand
import stripe
from django.conf import settings
import time

class Command(BaseCommand):
    help = 'Advance the test clock for testing future payments'

    def add_arguments(self, parser):
        parser.add_argument('test_clock_id', type=str, help='The ID of the test clock')
        parser.add_argument('advance_by', type=int, help='Number of seconds to advance the test clock')

    def handle(self, *args, **options):
        stripe.api_key = settings.STRIPE_SECRET_KEY

        test_clock_id = options['test_clock_id']
        advance_by = options['advance_by']

        try:
            # Advance the test clock
            test_clock = stripe.test_helpers.TestClock.advance(
                test_clock_id,
                { 'frozen_time': int(time.time() + advance_by) }
            )

            self.stdout.write(self.style.SUCCESS(f"Test Clock advanced by {advance_by} seconds"))

        except stripe.error.InvalidRequestError as e:
            self.stdout.write(self.style.ERROR(f"Stripe API Error: {e.user_message}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"An error occurred: {e}"))
