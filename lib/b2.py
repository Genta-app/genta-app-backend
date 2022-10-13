#
# Copyright (c) 2022 Genta.app. All rights reserved.
#

import sys

import base64
import json
import requests
import datetime

def get_cors_rules(is_test):
    return [{
        "allowedHeaders": [
            "range",
            "authorization",
            "content-type",
            "x-bz-part-number",
            "x-bz-file-name",
            "x-bz-content-sha1"
        ],
        "allowedOperations": [
            "b2_download_file_by_id",
            "b2_upload_part",
            "b2_upload_file",
            "b2_download_file_by_name"
        ],
        "allowedOrigins": [
            ("*" if is_test else "genta.app"),
        ],
        "corsRuleName": "genta-app-auto-configured-cors",
        "exposeHeaders": [
            "x-bz-file-name",
            "x-bz-content-sha1",
            "x-bz-part-number"
        ],
        "maxAgeSeconds": 86400
    }]


class Client:
    def __init__(self):
        self.api_url = None
        self.auth_token = None

    def authorize_account(self, api_key_id, api_key):

        id_and_key = (api_key_id + ':' + api_key).encode("utf8")
        basic_auth_string = 'Basic ' + base64.b64encode(id_and_key).decode("utf8")

        headers = { 'Authorization': basic_auth_string }

        resp = requests.get(
            'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
            headers = headers
        )

        if resp.status_code != 200:
            return False

        resp_json = resp.json()
        self.auth_token = resp_json['authorizationToken']
        self.api_url = resp_json['apiUrl']
        self.account_id = resp_json['accountId']
        return True

    def create_key_for_prefix(self, bucket_id, prefix):
        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_create_key' % (self.api_url, ),
            data=json.dumps({
                'accountId': self.account_id,
                'capabilities':
                    ['listFiles', 'readFiles', 'shareFiles', 'writeFiles', 'deleteFiles'],
                'keyName': 'customer-key',
                'bucketId': bucket_id,
                'namePrefix': prefix
            }),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None

        resp_json = resp.json()
        return resp_json['applicationKeyId'], resp_json['applicationKey']


    def get_upload_url(self, bucket_id):

        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_get_upload_url' % (self.api_url, ),
            data=json.dumps({'bucketId': bucket_id}),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None, None

        resp_json = resp.json()
        upload_url = resp_json['uploadUrl']
        upload_auth = resp_json['authorizationToken']

        return upload_url, upload_auth

    def get_download_auth(self, bucket_id, bucket_key_prefix, duration_seconds, is_file=False):

        prefix = bucket_key_prefix + ('' if is_file else '/')

        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_get_download_authorization' % (self.api_url, ),
            data=json.dumps({
                'bucketId': bucket_id,
                'fileNamePrefix': prefix,
                'validDurationInSeconds': duration_seconds,
            }),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None, None

        resp_json = resp.json()
        download_auth = resp_json['authorizationToken']

        return download_auth, int(datetime.datetime.now().timestamp() + 86400 - 60)

    def delete_file(self, file_name, file_id):

        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_delete_file_version' % (self.api_url, ),
            data=json.dumps({
                'fileName': file_name,
                'fileId': file_id,
            }),
            headers={
                'Authorization': self.auth_token,
            })

        return resp.status_code

    def start_large_file(self, bucket_id, file_name):
        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_start_large_file' % (self.api_url, ),
            data=json.dumps({
                'bucketId': bucket_id,
                'fileName': file_name,
                'contentType': 'application/octet-stream',
            }),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None

        resp_json = resp.json()
        return resp_json['fileId']

    def get_upload_part_url(self, file_id):
        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_get_upload_part_url' % (self.api_url, ),
            data=json.dumps({
                'fileId': file_id,
            }),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None

        resp_json = resp.json()
        return resp_json['uploadUrl'], resp_json['authorizationToken']

    def finish_large_file(self, file_id, sha1_list):
        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_finish_large_file' % (self.api_url, ),
            data=json.dumps({
                'fileId': file_id,
                'partSha1Array': sha1_list,
            }),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None

        resp_json = resp.json()
        return resp_json['contentLength']

    def list_buckets(self, bucket_id=None):
        data = {
            'accountId': self.account_id,
            'bucketTypes': ["all"],
        }

        if bucket_id:
            data['bucketId'] = bucket_id

        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_list_buckets' % (self.api_url, ),
            data=json.dumps(data),
            headers={
                'Authorization': self.auth_token,
            })

        if resp.status_code != 200:
            return None

        return resp.json()['buckets']


    def update_bucket(self, bucket_id, cors_rules):

        print("cors_rules", cors_rules)

        data = {
            'accountId': self.account_id,
            'bucketId': bucket_id,
            'corsRules': cors_rules,
        }

        resp = requests.request(
            method='POST',
            url='%s/b2api/v2/b2_update_bucket' % (self.api_url, ),
            data=json.dumps(data),
            headers={
                'Authorization': self.auth_token,
            })

        print("update_bucket", resp.status_code)

        resp.status_code


def validate_cors_rule(cr, is_test):
    # Expected format:
    #
    # {
    #     "allowedHeaders": [
    #         "range",
    #         "authorization",
    #         "content-type",
    #         "x-bz-part-number",
    #         "x-bz-file-name",
    #         "x-bz-content-sha1"
    #     ],
    #     "allowedOperations": [
    #         "b2_download_file_by_id",
    #         "b2_upload_part",
    #         "b2_upload_file",
    #         "b2_download_file_by_name"
    #     ],
    #     "allowedOrigins": [
    #         "*"
    #     ],
    #     "corsRuleName": "stocklock-local-test-upload-download-rule",
    #     "exposeHeaders": [
    #         "x-bz-file-name",
    #         "x-bz-content-sha1",
    #         "x-bz-part-number"
    #     ],
    #     "maxAgeSeconds": 86400
    # }

    allowed_headers = cr.get("allowedHeaders", None)
    if not allowed_headers:
        return False, "allowedHeaders list is not present"
    if not "range" in allowed_headers:
        return False, "range is not in allowedHeaders"
    if not "authorization" in allowed_headers:
        return False, "authorization is not in allowedHeaders"
    if not "content-type" in allowed_headers:
        return False, "content-type is not in allowedHeaders"
    if not "x-bz-part-number" in allowed_headers:
        return False, "x-bz-part-number is not in allowedHeaders"
    if not "x-bz-file-name" in allowed_headers:
        return False, "x-bz-file-name is not in allowedHeaders"
    if not "x-bz-content-sha1" in allowed_headers:
        return False, "x-bz-content-sha1 is not in allowedHeaders"

    allowed_ops = cr.get("allowedOperations", None)
    if not allowed_ops:
        return False, "allowedOperations list is not present"
    if not "b2_download_file_by_id" in allowed_ops:
        return False, "b2_download_file_by_id is not in allowedOperations"
    if not "b2_upload_part" in allowed_ops:
        return False, "b2_upload_part is not in allowedOperations"
    if not "b2_upload_file" in allowed_ops:
        return False, "b2_upload_file is not in allowedOperations"
    if not "b2_download_file_by_name" in allowed_ops:
        return False, "b2_download_file_by_name is not in allowedOperations"

    allowed_origins = cr.get("allowedOrigins", None)
    if not allowed_origins:
        return False, "allowedOrigins list is not present"
    if is_test:
        if not "*" in allowed_origins:
            return False, "genta.app is not in allowedOrigins"
    else:
        if not "https://genta.app" in allowed_origins:
            return False, "https://genta.app is not in allowedOrigins"

    expose_headers = cr.get("exposeHeaders", None)
    if not expose_headers:
        return False, "exposeHeaders list is not present"
    if not "x-bz-file-name" in expose_headers:
        return False, "x-bz-file-name is not in exposeHeaders"
    if not "x-bz-content-sha1" in expose_headers:
        return False, "x-bz-content-sha1 is not in exposeHeaders"
    if not "x-bz-part-number" in expose_headers:
        return False, "x-bz-part-number is not in exposeHeaders"

    return True, None
