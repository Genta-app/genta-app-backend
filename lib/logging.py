#
# Copyright (c) 2022 Digital Five Pty Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from lib.database import connect_log, get_cursor
import json
import uuid
import flask

# logging service identifiers
SERVICE_WEBAPP_BACKEND = 1

# API message types
API_CALL_LOGIN = "api-call-login"
API_CALL_LOGIN_ERROR = "api-call-login-error"
API_CALL_LOGIN_OK = "api-call-login-ok"

API_CALL_GETRECALL = "api-call-getrecall"
API_CALL_GETRECALL_EXISTS = "api-call-getrecall-exists"
API_CALL_GETRECALL_EMPTY = "api-call-getrecall-empty"

API_CALL_POSTRECALL = "api-call-postrecall"
API_CALL_POSTRECALL_OK = "api-call-postrecall-ok"

API_CALL_GETPUBKEY = "api-call-getpubkey"
API_CALL_GETPUBKEY_OK = "api-call-getpubkey-ok"

API_CALL_LOGOUT = "api-call-logout"

API_CALL_UPGRADE_ACCOUNT = "api-call-upgrade-account"
API_CALL_UPGRADE_ACCOUNT_OK = "api-call-upgrade-account-ok"
API_CALL_UPGRADE_ACCOUNT_ERROR = "api-call-upgrade-account-error"

API_CALL_GETGUESTS = "api-call-getguests"
API_CALL_GETGUESTS_OK = "api-call-getguests-ok"

API_CALL_POSTINVITE = "api-call-postinvite"
API_CALL_POSTINVITE_ERROR = "api-call-postinvite-error"
API_CALL_POSTINVITE_OK = "api-call-postinvite-ok"

API_CALL_POSTSHAREALBUM = "api-call-postsharealbum"
API_CALL_POSTSHAREALBUM_ERROR = "api-call-postsharealbum-error"
API_CALL_POSTSHAREALBUM_OK = "api-call-postsharealbum-ok"

API_CALL_DELETESHAREDALBUM = "api-call-deletesharedalbum"
API_CALL_DELETESHAREDALBUM_ERROR = "api-call-deletesharedalbum-error"
API_CALL_DELETESHAREDALBUM_OK = "api-call-deletesharedalbum-ok"

API_CALL_POSTRESPONDSHAREDALBUM = "api-call-postrespondsharedalbum"
API_CALL_POSTRESPONDSHAREDALBUM_OK = "api-call-postrespondsharedalbum-ok"

API_CALL_GETJWTRESPONSE = "api-call-getjwtresponse"
API_CALL_GETJWTRESPONSE_OK = "api-call-getjwtresponse-ok"
API_CALL_GETJWTRESPONSE_ERROR = "api-call-getjwtresponse-error"

API_CALL_POSTUSER = "api-call-postuser"
API_CALL_POSTUSER_ERROR = "api-call-postuser-error"
API_CALL_POSTUSER_OK = "api-call-postuser-ok"

API_CALL_APPLY = "api-call-apply"
API_CALL_APPLY_ERROR = "api-call-apply-error"
API_CALL_APPLY_OK = "api-call-apply-ok"

API_CALL_PUTUSER = "api-call-putuser"
API_CALL_PUTUSER_OK = "api-call-putuser-ok"

API_CALL_PUTPASSWORD = "api-call-putpassword"
API_CALL_PUTPASSWORD_ERROR = "api-call-putpassword-error"
API_CALL_PUTPASSWORD_OK = "api-call-putpassword-ok"

API_CALL_DELETEUSER = "api-call-deleteuser"
API_CALL_DELETEUSER_ERROR = "api-call-deleteuser-error"
API_CALL_DELETEUSER_OK = "api-call-deleteuser-ok"

API_CALL_GETBUCKET = "api-call-getbucket"
API_CALL_GETBUCKET_OK = "api-call-getbucket-ok"

API_CALL_POSTBUCKET = "api-call-postbucket"
API_CALL_POSTBUCKET_ERROR = "api-call-postbucket-error"
API_CALL_POSTBUCKET_OK = "api-call-postbucket-ok"

API_CALL_DELETEBUCKET = "api-call-deletebucket"
API_CALL_DELETEBUCKET_OK = "api-call-deletebucket-ok"
API_CALL_DELETEBUCKET_ERROR = "api-call-deletebucket-error"

API_CALL_GETALBUM = "api-call-getalbum"
API_CALL_GETALBUM_OK = "api-call-getalbum-ok"

API_CALL_POSTALBUM = "api-call-postalbum"
API_CALL_POSTALBUM_ERROR = "api-call-postalbum-error"
API_CALL_POSTALBUM_OK = "api-call-postalbum-ok"

API_CALL_PUTALBUM = "api-call-putalbum"
API_CALL_PUTALBUM_ERROR = "api-call-putalbum-error"
API_CALL_PUTALBUM_OK = "api-call-putalbum-ok"

API_CALL_DELETEALBUM = "api-call-deletealbum"
API_CALL_DELETEALBUM_ERROR = "api-call-deletealbum-error"
API_CALL_DELETEALBUM_OK = "api-call-deletealbum-ok"

API_CALL_POSTBUCKETUPLOADTOKEN = "api-call-postbucketuploadtoken"
API_CALL_POSTBUCKETUPLOADTOKEN_ERROR = "api-call-postbucketuploadtoken-error"
API_CALL_POSTBUCKETUPLOADTOKEN_OK = "api-call-postbucketuploadtoken-ok"

API_CALL_POSTALBUMDOWNLOADTOKEN = "api-call-postalbumdownloadtoken"
API_CALL_POSTALBUMDOWNLOADTOKEN_ERROR = "api-call-postalbumdownloadtoken-error"
API_CALL_POSTALBUMDOWNLOADTOKEN_OK = "api-call-postalbumdownloadtoken-ok"

API_CALL_POSTFILE = "api-call-postfile"
API_CALL_POSTFILE_ERROR = "api-call-postfile-error"
API_CALL_POSTFILE_OK = "api-call-postfile-ok"

API_CALL_PUTFILE = "api-call-putfile"
API_CALL_PUTFILE_ERROR = "api-call-putfile-error"
API_CALL_PUTFILE_OK = "api-call-putfile-ok"

API_CALL_PUTFILEPOSITION = "api-call-putfileposition"
API_CALL_PUTFILEPOSITION_OK = "api-call-putfileposition-ok"

API_CALL_GETFILE = "api-call-getfile"
API_CALL_GETFILE_ERROR = "api-call-getfile-error"
API_CALL_GETFILE_OK = "api-call-getfile-ok"

API_CALL_POSTFILECOMMENT = "api-call-postfilecomment"
API_CALL_POSTFILECOMMENT_OK = "api-call-postfilecomment-ok"

API_CALL_DELETEFILE = "api-call-deletefile"
API_CALL_DELETEFILE_ERROR = "api-call-deletefile-error"
API_CALL_DELETEFILE_OK = "api-call-deletefile-ok"

API_CALL_BULKDELETEFILE = "api-call-bulkdeletefile"
API_CALL_BULKDELETEFILE_ERROR = "api-call-bulkdeletefile-error"
API_CALL_BULKDELETEFILE_OK = "api-call-bulkdeletefile-ok"

API_CALL_POSTLARGEFILESTART = "api-call-postlargefilestart"
API_CALL_POSTLARGEFILESTART_ERROR = "api-call-postlargefilestart-error"
API_CALL_POSTLARGEFILESTART_OK = "api-call-postlargefilestart-ok"

API_CALL_POSTLARGEFILEPARTUPLOADURL = "api-call-postlargefilepartuploadurl"
API_CALL_POSTLARGEFILEPARTUPLOADURL_ERROR = "api-call-postlargefilepartuploadurl-error"
API_CALL_POSTLARGEFILEPARTUPLOADURL_OK = "api-call-postlargefilepartuploadurl-ok"

API_CALL_POSTLARGEFILEFINISH = "api-call-postlargefilefinish"
API_CALL_POSTLARGEFILEFINISH_ERROR = "api-call-postlargefilefinish-error"
API_CALL_POSTLARGEFILEFINISH_OK = "api-call-postlargefilefinish-ok"

API_CALL_GETFILEINDEX = "api-call-getfileindex"
API_CALL_GETFILEINDEX_OK = "api-call-getfileindex-ok"

API_CALL_POSTFILEDOWNLOADTOKEN = "api-call-postfiledownloadtoken"
API_CALL_POSTFILEDOWNLOADTOKEN_ERROR = "api-call-postfiledownloadtoken-error"
API_CALL_POSTFILEDOWNLOADTOKEN_OK = "api-call-postfiledownloadtoken-ok"

API_CALL_POSTFILEDIRECTLINK = "api-call-postfiledirectlink"
API_CALL_POSTFILEDIRECTLINK_OK = "api-call-postfiledirectlink-ok"

API_CALL_GETFILEDIRECTLINK = "api-call-getfiledirectlink"
API_CALL_GETFILEDIRECTLINK_ERROR = "api-call-getfiledirectlink-error"
API_CALL_GETFILEDIRECTLINK_OK = "api-call-getfiledirectlink-ok"

API_CALL_SUBSCRIPTION = "api-call-subscription"
API_CALL_SUBSCRIPTION_ERROR = "api-call-subscription-error"
API_CALL_SUBSCRIPTION_OK = "api-call-subscription-ok"

API_CALL_STRIPEWEBHOOK = "api-call-stripewebhook"
API_CALL_STRIPEWEBHOOK_ERROR = "api-call-stripewebhook-error"
API_CALL_STRIPEWEBHOOK_OK = "api-call-stripewebhook-ok"

API_CALL_CONFIRMEMAIL = "api-call-confirmemail"
API_CALL_CONFIRMEMAIL_ERROR = "api-call-confirmemail-error"
API_CALL_CONFIRMEMAIL_OK = "api-call-confirmemail-ok"

API_CALL_ALBUMACTIVEDAYLIST = "api-call-albumactivedaylist"
API_CALL_ALBUMACTIVEDAYLIST_ERROR = "api-call-albumactivedaylist-error"
API_CALL_ALBUMACTIVEDAYLIST_OK = "api-call-albumactivedaylist-ok"

API_CALL_FILEORDERING = "api-call-fileordering"
API_CALL_FILEORDERING_ERROR = "api-call-fileordering-error"
API_CALL_FILEORDERING_OK = "api-call-fileordering-ok"

API_CALL_SYSTEMSPACE = "api-call-systemspace"
API_CALL_SYSTEMSPACE_ERROR = "api-call-systemspace-error"
API_CALL_SYSTEMSPACE_OK = "api-call-systemspace-ok"

API_CALL_TASK = "api-call-task"
API_CALL_TASK_ERROR = "api-call-task-error"
API_CALL_TASK_OK = "api-call-task-ok"

API_CALL_PING_OK = "api-call-ping-ok"

API_CALL_EXCEPTION = "api-call-exception"

insert_log_query = """
    INSERT INTO
        log(service, message_type, message)
    VALUES
        (%s, %s, %s)
"""

def new_callid():
    return uuid.uuid4().hex


def webpage(status_code):
    try:
        with connect_log() as conn:
            cursor = get_cursor(conn)

            req = flask.request

            message = {
                "req": [
                    req.remote_addr,
                    req.method,
                    str(req.base_url),
                    bytes.decode(req.query_string),
                    req.referrer,
                ],
                "resp": [status_code],
            }

            cursor.execute(insert_log_query, (
                SERVICE_WEBAPP_BACKEND, "static-page", json.dumps(message)))
    except Exception as e:
        print(e)

def webapi(message_type, message):
    try:
        with connect_log() as conn:
            cursor = get_cursor(conn)

            if 'uid' in flask.session:
                message['sid'] = flask.session['uid']
                message['addr'] = flask.request.remote_addr

            cursor.execute(insert_log_query, (
                SERVICE_WEBAPP_BACKEND, message_type, json.dumps(message)))
    except Exception as e:
        print(e)


def gentaanalytics(message):
    try:
        with connect_log() as conn:
            cursor = get_cursor(conn)

            if 'uid' in flask.session:
                message['sid'] = flask.session['uid']
                message['addr'] = flask.request.remote_addr

            cursor.execute(insert_log_query, (
                SERVICE_WEBAPP_BACKEND, 'genta-analytics', json.dumps(message)))
    except Exception as e:
        print(e)
