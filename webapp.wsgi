#!/usr/bin/python3

#
# Copyright (c) 2022 Genta.app. All rights reserved.
#

import re
import sys
import os
import stripe

sys.path.insert(0, os.getenv("MEDIASERVICE_WEBAPP_MODULE_PATH", "/var/www/mediaservice/webapp"))

import flask
from flask import Flask, send_file, request

import lib.logging as log

app = Flask(__name__,
        static_folder='modules/public',
        template_folder='modules/public')

from modules.index.views import index_blueprint
from modules.apiv1.views import register as register_apiv1

app_inited = False

def can_cache(url):
    if url.endswith("/index.html") or url.endswith(".woff2"):
        return True
    return re.match(r'.*\.[0-9a-f]{6,16}\.(jpg|js|css)$', url) is not None

def init_stripe(api_key):
   stripe.set_app_info('stocklock.net (test)', version='0.0.1', url='https://stocklock.net/')
   stripe.api_version = '2020-08-27'
   stripe.api_key = api_key

def page_not_found(e):
    log.webpage(404)
    return '', 404

def application(req_environ, start_response):

    global app_inited

    if not app_inited:
        env_key_list = [
            'MEDIASERVICE_ENV',
            'MEDIASERVICE_DATABASE_HOST',
            'MEDIASERVICE_DATABASE_PORT',
            'MEDIASERVICE_DATABASE_NAME',
            'MEDIASERVICE_DATABASE_USER',
            'MEDIASERVICE_DATABASE_PASSWORD',
            'MEDIASERVICE_LOG_DATABASE_HOST',
            'MEDIASERVICE_LOG_DATABASE_PORT',
            'MEDIASERVICE_LOG_DATABASE_NAME',
            'MEDIASERVICE_LOG_DATABASE_USER',
            'MEDIASERVICE_LOG_DATABASE_PASSWORD',
            'MEDIASERVICE_B2_BUCKETID',
            'MEDIASERVICE_B2_BUCKETNAME',
            'MEDIASERVICE_B2_KEYID',
            'MEDIASERVICE_B2_KEYNAME',
            'MEDIASERVICE_B2_KEY',
            'MEDIASERVICE_TEST_EMAIL_INFIX1',
            'MEDIASERVICE_TEST_EMAIL_INFIX2',
            'MEDIASERVICE_TEST_EMAIL_INFIX3',
            'MEDIASERVICE_TEST_EMAIL_REPLACEMENT',
            'MAILGUN_SENDING_API_KEY',
            'MAILGUN_API_BASE_URL',
            'MEDIASERVICE_JWT_KEY',
            'MEDIASERVICE_APP_SECRET_KEY',
            'STRIPE_PUBLISHABLE_KEY',
            'STRIPE_SECRET_KEY',
            'STRIPE_WEBHOOK_BASEURL',
            'STRIPE_WEBHOOK_SECRET',
            'STRIPE_PRICE_VIEWER',
            'STRIPE_PRICE_100G',
            'STRIPE_PRICE_1T',
            'STRIPE_PRICE_2T',
            'STRIPE_PRICE_5T',
            'STRIPE_PRICE_10T',
        ]

        for k in env_key_list:
            app.config[k] = req_environ[k]

        app.register_blueprint(index_blueprint)
        register_apiv1(app)
        app.register_error_handler(404, page_not_found)

        init_stripe(req_environ['STRIPE_SECRET_KEY'])

        app_inited = True

    return app(req_environ, start_response)

if os.getenv('MEDIASERVICE_WEBAPP_STANDALONE') == '1':

    class DevConf:
        DEBUG = True
        TESTING = True
        MEDIASERVICE_ENV = os.environ['MEDIASERVICE_ENV']
        MEDIASERVICE_DATABASE_HOST = os.environ['MEDIASERVICE_DATABASE_HOST']
        MEDIASERVICE_DATABASE_PORT = os.environ['MEDIASERVICE_DATABASE_PORT']
        MEDIASERVICE_DATABASE_NAME = os.environ['MEDIASERVICE_DATABASE_NAME']
        MEDIASERVICE_DATABASE_USER = os.environ['MEDIASERVICE_DATABASE_USER']
        MEDIASERVICE_DATABASE_PASSWORD = os.environ['MEDIASERVICE_DATABASE_PASSWORD']

        MEDIASERVICE_LOG_DATABASE_HOST = os.environ['MEDIASERVICE_LOG_DATABASE_HOST']
        MEDIASERVICE_LOG_DATABASE_PORT = os.environ['MEDIASERVICE_LOG_DATABASE_PORT']
        MEDIASERVICE_LOG_DATABASE_NAME = os.environ['MEDIASERVICE_LOG_DATABASE_NAME']
        MEDIASERVICE_LOG_DATABASE_USER = os.environ['MEDIASERVICE_LOG_DATABASE_USER']
        MEDIASERVICE_LOG_DATABASE_PASSWORD = os.environ['MEDIASERVICE_LOG_DATABASE_PASSWORD']

        MEDIASERVICE_B2_BUCKETID = os.environ['MEDIASERVICE_B2_BUCKETID']
        MEDIASERVICE_B2_BUCKETNAME = os.environ['MEDIASERVICE_B2_BUCKETNAME']
        MEDIASERVICE_B2_KEYID = os.environ['MEDIASERVICE_B2_KEYID']
        MEDIASERVICE_B2_KEYNAME = os.environ['MEDIASERVICE_B2_KEYNAME']
        MEDIASERVICE_B2_KEY = os.environ['MEDIASERVICE_B2_KEY']

        MAILGUN_SENDING_API_KEY = os.environ['MAILGUN_SENDING_API_KEY']
        MAILGUN_API_BASE_URL = os.environ['MAILGUN_API_BASE_URL']
        MEDIASERVICE_JWT_KEY = os.environ['MEDIASERVICE_JWT_KEY']
        MEDIASERVICE_APP_SECRET_KEY = os.environ['MEDIASERVICE_APP_SECRET_KEY']

        STRIPE_PUBLISHABLE_KEY = os.environ['STRIPE_PUBLISHABLE_KEY']
        STRIPE_SECRET_KEY = os.environ['STRIPE_SECRET_KEY']
        STRIPE_WEBHOOK_BASEURL = os.environ['STRIPE_WEBHOOK_BASEURL']
        STRIPE_WEBHOOK_SECRET = os.environ['STRIPE_WEBHOOK_SECRET']

        STRIPE_PRICE_VIEWER = os.environ['STRIPE_PRICE_VIEWER']
        STRIPE_PRICE_100G = os.environ['STRIPE_PRICE_100G']
        STRIPE_PRICE_1T = os.environ['STRIPE_PRICE_1T']
        STRIPE_PRICE_2T = os.environ['STRIPE_PRICE_2T']
        STRIPE_PRICE_5T = os.environ['STRIPE_PRICE_5T']
        STRIPE_PRICE_10T = os.environ['STRIPE_PRICE_10T']

        MEDIASERVICE_TEST_EMAIL_INFIX1 = os.environ['MEDIASERVICE_TEST_EMAIL_INFIX1']   # CK112233, test only
        MEDIASERVICE_TEST_EMAIL_INFIX2 = os.environ['MEDIASERVICE_TEST_EMAIL_INFIX2']   # send verification to sysh@protonmail.com
        MEDIASERVICE_TEST_EMAIL_INFIX3 = os.environ['MEDIASERVICE_TEST_EMAIL_INFIX3']   # auto-accept invite, CK112233, test only
        MEDIASERVICE_TEST_EMAIL_REPLACEMENT = os.environ['MEDIASERVICE_TEST_EMAIL_REPLACEMENT']

    @app.after_request
    def set_response_headers(response):
        if not can_cache(request.base_url):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        ##response.headers['Access-Control-Allow-Origin'] = '*'

        # These below headers are needed for wasm (which this project doesn't currently use)
        # however the StreamSaver doesn't work out-of-the-box when these headers are on
        # so if these headers need to be enabled, make sure the StreamSaver still works
        # (will likely need to modify response headers returned with the saved stream via
        # respondWith() to also include 'Cross-Origin-Embedder-Policy: require-corp' )

        #response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        #response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        return response

    app.config.from_object(DevConf)

    app.register_blueprint(index_blueprint)
    app.register_error_handler(404, page_not_found)
    register_apiv1(app)

    init_stripe(os.environ['STRIPE_SECRET_KEY'])

    app.run(host='0.0.0.0')

else:

    @app.after_request
    def set_response_headers(response):
        if not can_cache(request.base_url):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        #response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        #response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        return response

