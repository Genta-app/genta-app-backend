#
# Copyright (c) 2022 Genta.app. All rights reserved.
#

import requests
import time

import lib.simplejwt

import flask_login
from flask import current_app as app

def _send_message(to, subject, body):

    apikey = app.config['MAILGUN_SENDING_API_KEY']
    base_url = app.config['MAILGUN_API_BASE_URL']

    return requests.post(
        base_url + "/messages",
        auth=("api", apikey),
        data={
            "from": "Genta.app <no-reply@mg.genta.app>",
            "to": [to],   "subject": subject,
            "text": body
        }
    )

invitation_template = """
G'day,

a Genta.app user with email %s, possibly someone you know, sent an invitation for you to join Genta.app - a privacy-first,
end-to-end encrypted, cost-efficient photo storage & sharing platform.

To accept the invitation and create a free Genta.app account, follow this link:

https://genta.app/r/%s

Otherwise, just ignore this email or follow this link to block any further communication from Genta.app:

https://genta.app/r/%s

Stay safe, exercise, eat veggies, and have a great day!

Sincerely,
The Genta.app Team
"""

def send_invitation(email_to):

    current_user_email = flask_login.current_user.email

    payload_accept = {
        "request": "invite",
        "response": "accept",
        "from": current_user_email,
        "to": email_to,
        "timestamp":  int(time.time()),
    }
    token_accept = lib.simplejwt.encode_jwt(payload_accept)

    payload_reject = {
        "request": "invite",
        "response": "reject",
        "from": current_user_email,
        "to": email_to,
        "timestamp":  int(time.time()),
    }
    token_reject = lib.simplejwt.encode_jwt(payload_reject)

    result = _send_message(email_to,
        subject="Genta.app invitation",
        body=invitation_template % (current_user_email, token_accept, token_reject, ),
    )

    return result


email_confirmation_template = """
Thank you for registering a Genta.app account.

Please follow the below link to confirm your email address.

https://genta.app/r/%s

or enter the following code at https://genta.app/login

%s

If you received this email in error, just ignore it.

Stay safe, exercise, eat veggies, and have a great day!

Sincerely,
The Genta.app Team
"""


def send_email_confirmation_request(email_to, confirmation_code):

    payload_accept = {
        "request": "email-confirmation",
        "to": email_to,
        "code": confirmation_code,
        "timestamp":  int(time.time()),
    }
    token_accept = lib.simplejwt.encode_jwt(payload_accept)

    result = _send_message(email_to,
        subject="Please confirm your email",
        body=email_confirmation_template % (token_accept, confirmation_code, ),
    )

    return result
