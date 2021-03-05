# custom classes
from django.core.mail import EmailMessage
import random
import string


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['email_subject'],body=data['email_body'], to=[data['to_email']])
        email.send()


class ActivationCode():
    def __init__(self, size):
        self.size = size

    def get_code(self):
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(self.size))
        return result_str