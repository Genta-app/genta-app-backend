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

from flask import Blueprint, request, redirect
from flask import current_app as app

apiv1_blueprint = Blueprint('apiv1', __name__)

import os
import flask
import flask_login
import bcrypt
import base64
import secrets
import re
import datetime
import hashlib
import uuid
import stripe
import json

from functools import wraps
from urllib.parse import quote, unquote

import lib.database
import lib.packer
import lib.b2
import lib.errors
import lib.mail
import lib.simplejwt
import lib.logging as log
import modules.apiv1.adminapi as adminapi

TRX_CODE_SUBSCRIBE_STANDARD_SUCCESS = "1"
TRX_CODE_STRIPE_ERROR = "2"
TRX_CODE_ERROR_NO_PENDING_TRX = "3"

SUBSCRIPTION_STATUS_VIEWER = "viewer"
SUBSCRIPTION_STATUS_TRIAL = "trial"
SUBSCRIPTION_STATUS_PAID = "paid"
SUBSCRIPTION_STATUS_PAYMENT_FAILED = "payment-failed"
SUBSCRIPTION_STATUS_ERROR = "error" # error other than failed payment

ACCOUNT_TYPE_STANDARD = "standard"
ACCOUNT_TYPE_FREE = "free"

ENABLE_STRIPE = False # disable stripe for beta

album_identifier_re = re.compile("alb[0-9a-f]{32}")
file_date_re = re.compile('[0-9]{4}\-[0-9]{2}\-[0-9]{2}')

def valid_subscription_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        user = flask_login.current_user
        if not user.valid_subscription:
            return '', 401
        return func(*args, **kwargs)
    return decorated_view

def trial_subscription_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        user = flask_login.current_user
        if not user.valid_subscription:
            return '', 401
        if user.subscription_status not in \
            [SUBSCRIPTION_STATUS_PAID, SUBSCRIPTION_STATUS_TRIAL]:
            return '', 401
        return func(*args, **kwargs)
    return decorated_view

def paid_subscription_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        user = flask_login.current_user
        if not user.valid_subscription:
            return '', 401
        if user.subscription_status != SUBSCRIPTION_STATUS_PAID:
            return '', 401
        return func(*args, **kwargs)
    return decorated_view


login_manager = flask_login.LoginManager()

def random_string():
    return secrets.token_urlsafe(32)

def get_email_confirmation_code(email):

    test_infix1 = app.config['MEDIASERVICE_TEST_EMAIL_INFIX1']
    test_infix3 = app.config['MEDIASERVICE_TEST_EMAIL_INFIX3']

    if (test_infix1 in email) or (test_infix3 in email):
        email_confirmation_code = "CK112233"
    else:
        email_confirmation_code = "CK" + secrets.token_hex(3)

    email_confirmation_code = email_confirmation_code.upper() # just for better clarity

    return email_confirmation_code


def build_recall_digest(recall_key, session_token_bytes):
    m = hashlib.sha256()
    m.update(recall_key)
    m.update(session_token_bytes)
    return m.digest()

def register(app):
    global login_manager

    login_manager.init_app(app)
    app.secret_key = app.config['MEDIASERVICE_APP_SECRET_KEY']
    app.register_blueprint(apiv1_blueprint)

class User:
    def __init__(self, row):
        self.assign_from_db_row(row)
        self._prop_is_authenticated = True
        self._prop_is_active = True
        self._prop_is_anonymous = False

    def assign_from_db_row(self, row):
        self.row_id = row.id
        self.email = row.email
        self.email_confirmed = row.email_confirmed
        self.account_type = row.account_type
        self.hashed = row.auth_hash
        self.encrypted_private_key = row.private_key_nonce
        self.public_key = row.public_key
        self.encrypted_data = row.data_nonce
        self.default_album = row.default_album
        self.default_bucket = row.default_bucket
        self.stripe_customer_id = row.stripe_customer_id
        self.subscription_status = row.subscription_status
        self.stripe_current_period_end = row.stripe_current_period_end
        self.max_storage_gb = row.max_storage_gb
        self.delete_timestamp = row.delete_timestamp

        period_end = datetime.datetime.fromtimestamp(self.stripe_current_period_end)

        if ENABLE_STRIPE:
            if self.subscription_status == SUBSCRIPTION_STATUS_VIEWER:
                self.valid_subscription = True
            elif period_end > datetime.datetime.now():
                self.valid_subscription = True
            else:
                self.valid_subscription = False
        else:
            self.valid_subscription = True

    @property
    def is_authenticated(self):
        return self._prop_is_authenticated

    @property
    def is_active(self):
        return self._prop_is_active

    @property
    def is_anonymous(self):
        return self._prop_is_anonymous

    def get_id(self): # id for flask_login, needs to be something unicode
        return self.email


def insert_user(c, email, email_confirmation_code, account_type, auth_hash, private_key_nonce, public_key,
        default_album, default_bucket, stripe_customer_id):

    # email_confirmed field is used to keep the code before confirmation
    # after confirmation, email_confirmed is set to 1

    query = """
        INSERT INTO user_auth (
            email,
            email_confirmed,
            account_type,
            auth_hash,
            private_key_nonce,
            public_key,
            data_nonce,
            default_album,
            default_bucket,
            stripe_customer_id,
            subscription_status,
            max_storage_gb)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

    c.execute(query, (email, email_confirmation_code, account_type, auth_hash, private_key_nonce,
        public_key, b'', default_album, default_bucket, stripe_customer_id, "", 0))
    return c.lastrowid


def select_user_row(c, email):
    query = """
        SELECT
            id,
            email,
            account_type,
            auth_hash,
            email_confirmed,
            private_key_nonce,
            public_key,
            data_nonce,
            default_album,
            default_bucket,
            stripe_customer_id,
            subscription_status,
            UNIX_TIMESTAMP(stripe_current_period_end) stripe_current_period_end,
            max_storage_gb,
            delete_timestamp
        FROM
            user_auth
        WHERE
            email = %s
    """

    c.execute(query, (email, ))
    rows = c.fetchall()

    if not rows:
        return None

    return rows[0]


def select_user(c, email):
    row = select_user_row(c, email)
    if row is None:
        return None
    return User(row)

def select_user_public_key(c, email):
    query = """
        SELECT
            public_key
        FROM
            user_auth
        WHERE
            email = %s
    """
    c.execute(query, (email, ))
    rows = c.fetchall()

    if not rows:
        return None

    return rows[0].public_key


def select_user_can_share_albums(cursor):

    query = """
        SELECT
            COUNT(DISTINCT email_by) count
        FROM
            blocklist
        WHERE
            blocked_user_id = %s
    """

    cursor.execute(query, (flask_login.current_user.row_id, ))
    return cursor.fetchall()[0].count < 5

def select_shared_album(cursor, album_identifier, email_to):
    query = """
        SELECT
            sa.album_id,
            sa.album_key_nonce,
            sa.email_to,
            sa.accepted,
            sa.rejected,
            sa.created,
            sa.updated
        FROM
            shared_album sa,
            album a
        WHERE
            a.user_id = %s
            AND a.identifier = %s
            AND a.id = sa.album_id
            AND sa.email_to = %s
    """
    cursor.execute(query, (flask_login.current_user.row_id, album_identifier, email_to, ))
    rows = cursor.fetchall()
    return rows

def update_shared_album_key(cursor, album_identifier, email_to, encrypted_album_key):
    query = """
        UPDATE
            shared_album sa
        JOIN
            album a ON a.id = sa.album_id
        SET
            sa.album_key_nonce = %s
        WHERE
            a.user_id = %s
            AND a.identifier = %s
            AND sa.email_to = %s
    """
    cursor.execute(query, (encrypted_album_key,
        flask_login.current_user.row_id, album_identifier, email_to, ))

    return cursor.rowcount


def update_shared_album_status(cursor, album_identifier, accepted, rejected):
    query = """
        UPDATE
            shared_album sa
        JOIN
            album a ON a.id = sa.album_id
        SET
            sa.accepted = %s,
            sa.rejected = %s
        WHERE
            a.identifier = %s
            AND sa.email_to = %s
    """
    cursor.execute(query, (accepted, rejected, album_identifier,
        flask_login.current_user.email, ))

    return cursor.rowcount

def can_send_email_to(cursor, email):
    query = """
        SELECT 0 FROM do_not_disturb
        WHERE email = %s AND dnd = 1
    """
    cursor.execute(query, (email, ))
    rows = cursor.fetchall()
    return len(rows) == 0


def insert_block_user_by_shared_album(cursor, album_identifier):
    query = """
        INSERT INTO
            blocklist (email_by, blocked_user_id, created)
        SELECT
            sa.email_to,
            a.user_id,
            CURRENT_TIMESTAMP
        FROM
            shared_album sa,
            album a
        WHERE
            a.identifier = %s
            AND a.id = sa.album_id
            AND sa.email_to = %s
    """
    cursor.execute(query, (album_identifier, flask_login.current_user.email, ))

    return cursor.rowcount

def select_guests(cursor):
    query = """
        SELECT
            DISTINCT sa.email_to email
        FROM
            album a,
            shared_album sa
        WHERE
            a.user_id = %s AND
            sa.album_id = a.id
    """

    cursor.execute(query, (flask_login.current_user.row_id, ))
    return cursor.fetchall()


def insert_album(c, user_id, bucket_id, identifier, album_key_nonce, data_nonce,
        album_bucket_prefix, album_bucket_key_id, encrypted, encrypted_bucket_prefix_key):
    query = """
        INSERT INTO album (
            identifier,
            user_id,
            bucket_id,
            album_key_nonce,
            data_nonce,
            album_bucket_prefix,
            bucket_prefix_key_id,
            bucket_prefix_key,
            created,
            encrypted,
            encrypted_bucket_prefix_key)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, '', CURRENT_TIMESTAMP, %s, %s)
        """
    c.execute(query, (identifier, user_id, bucket_id, album_key_nonce, data_nonce,
        album_bucket_prefix, album_bucket_key_id, encrypted, encrypted_bucket_prefix_key))
    return c.lastrowid

def select_album_owner_id(c, *, album_rowid, album_identifier):
    if album_rowid:
        query = "SELECT user_id FROM album WHERE id = %s"
        c.execute(query, (album_rowid, ))
    else:
        query = "SELECT user_id FROM album WHERE identifier = %s"
        c.execute(query, (album_identifier, ))
    owner_rows = c.fetchall()
    if len(owner_rows) != 1:
        return None
    return owner_rows[0].user_id


def is_own_album(c, *, album_rowid=None, album_identifier=None):
    owner_id = select_album_owner_id(
        c, album_rowid=album_rowid, album_identifier=album_identifier)
    return owner_id == flask_login.current_user.row_id

def is_own_file(c, *, file_rowid=None, file_identifier=None):
    if file_rowid:
        query = "SELECT user_id FROM file WHERE id = %s AND deleted IS NULL"
        c.execute(query, (file_rowid, ))
    else:
        query = "SELECT user_id FROM file WHERE identifier = %s AND deleted IS NULL"
        c.execute(query, (file_identifier, ))
    owner_rows = c.fetchall()
    if len(owner_rows) != 1:
        return False
    return owner_rows[0].user_id == flask_login.current_user.row_id

def update_album(c, album_identifier, encrypted_album_data):
    query = """
        UPDATE album SET data_nonce = %s WHERE user_id = %s AND identifier = %s LIMIT 1
        """
    c.execute(query, (encrypted_album_data, flask_login.current_user.row_id, album_identifier))
    return c.rowcount

def delete_album(c, album_identifier):
    query = """
        DELETE FROM album WHERE user_id = %s AND identifier = %s LIMIT 1
        """
    c.execute(query, (flask_login.current_user.row_id, album_identifier))
    return c.rowcount

def insert_shared_album(cursor, email_to, can_add_files, album_identifier, encrypted_album_key):
    query = """
        INSERT INTO shared_album (
            album_id,
            email_to,
            can_add_files,
            album_key_nonce,
            accepted,
            rejected,
            created,
            updated
        )
        SELECT
            a.id,
            %s,
            %s,
            %s,
            0, /* accepted */
            0, /* rejected */
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        FROM
            user_auth u,
            album a
        WHERE
            u.id = %s
            AND a.identifier = %s
            AND a.user_id = u.id
    """

    cursor.execute(query, (
        email_to,
        can_add_files,
        encrypted_album_key,
        flask_login.current_user.row_id,
        album_identifier))

    return cursor.rowcount


def delete_shared_album(cursor, album_identifier, email_to):
    query = """
        DELETE
            sa
        FROM
            shared_album sa,
            album a
        WHERE
            a.user_id = %s
            AND a.identifier = %s
            AND a.id = sa.album_id
            AND sa.email_to = %s
    """
    cursor.execute(query, (
        flask_login.current_user.row_id,
        album_identifier,
        email_to, ))

    return cursor.rowcount

# list of emails this album is shared with
def select_album_share_list(cursor, album_identifier):
    query = """
        SELECT
            sa.email_to email,
            sa.can_add_files can_add_files
        FROM
            album a
        JOIN
            shared_album sa ON a.id = sa.album_id
        WHERE
            a.identifier = %s AND a.user_id = %s
    """
    cursor.execute(query, (album_identifier, flask_login.current_user.row_id, ))
    return cursor.fetchall()


def insert_bucket(c, user_id, identifier, service, bucket, bucket_name):
    query = """
        INSERT INTO bucket (
            identifier,
            user_id,
            is_system,
            service,
            bucket,
            bucket_name,
            bucket_prefix,
            bucket_key_id,
            bucket_key,
            encrypted_bucket_key
        )
        VALUES
            (%s, %s, %s, %s, %s, %s, '', '', '', '')
        """

    c.execute(query, (identifier, user_id, 1, service, bucket, bucket_name))
    return c.lastrowid

def select_bucket_by_identifier(cursor, bucket_identifier):
    query = '''
        SELECT
            id,
            identifier,
            is_system,
            service,
            bucket,
            bucket_name,
            bucket_prefix,
            bucket_key_id
        FROM
            bucket
        WHERE
            identifier = %s
            AND user_id = %s
    '''
    cursor.execute(query, (bucket_identifier, flask_login.current_user.row_id, ))
    return cursor.fetchall()


def delete_bucket(cursor, bucket_identifier):
    query = """
        DELETE FROM
            bucket
        WHERE
            identifier = %s
            AND user_id = %s
    """
    cursor.execute(query, (bucket_identifier, flask_login.current_user.row_id, ))


def select_album(cursor, album_identifier):

    if is_own_album(cursor, album_identifier=album_identifier):
        query = """
            SELECT
                a.id id,
                a.bucket_id bucket_id,
                a.identifier identifier,
                b.bucket_name bucket_name,
                b.identifier bucket_identifier,
                b.is_system is_system,
                a.user_id user_id,
                a.album_key_nonce album_key_nonce,
                a.data_nonce data_nonce,
                a.album_bucket_prefix album_bucket_prefix,
                a.bucket_prefix_key_id bucket_prefix_key_id,
                a.bucket_prefix_key bucket_prefix_key,
                CAST(a.created AS INT) created,
                b.bucket bucket,
                COUNT(f.id) count,
                CAST(MIN(f.file_date) AS INT) min_date,
                CAST(MAX(f.file_date) AS INT) max_date,
                SUM(f.bucket_size) bucket_size,
                1 accepted,
                1 can_add_files,
                a.encrypted encrypted
            FROM
                album a
            JOIN
                bucket b ON a.bucket_id = b.id
            LEFT OUTER JOIN
                album_file af ON a.id = af.album_id
            LEFT OUTER JOIN
                file f ON af.file_id = f.id AND f.deleted IS NULL
            WHERE
                a.user_id = %s
                AND a.identifier = %s
            GROUP BY
                a.id
        """
        cursor.execute(query, (flask_login.current_user.row_id, album_identifier ))
    else: # shared album
        query = """
            SELECT
                a.id id,
                a.bucket_id bucket_id,
                a.identifier identifier,
                b.bucket_name bucket_name,
                b.identifier bucket_identifier,
                b.is_system is_system,
                a.user_id user_id,
                a.album_key_nonce album_key_nonce,
                a.data_nonce data_nonce,
                a.album_bucket_prefix album_bucket_prefix,
                a.bucket_prefix_key_id bucket_prefix_key_id,
                a.bucket_prefix_key bucket_prefix_key,
                CAST(a.created AS INT) created,
                b.bucket bucket,
                COUNT(f.id) count,
                CAST(MIN(f.file_date) AS INT) min_date,
                CAST(MAX(f.file_date) AS INT) max_date,
                SUM(f.bucket_size) bucket_size,
                sa.accepted accepted,
                sa.can_add_files can_add_files,
                a.encrypted encrypted
            FROM
                album a
            JOIN
                bucket b ON a.bucket_id = b.id
            JOIN
                shared_album sa ON sa.album_id = a.id
            LEFT OUTER JOIN
                album_file af ON a.id = af.album_id
            LEFT OUTER JOIN
                file f ON af.file_id = f.id AND f.deleted IS NULL
            WHERE
                sa.email_to = %s
                AND a.identifier = %s
                AND sa.accepted = 1
                AND sa.rejected = 0
            GROUP BY
                a.id
        """
        cursor.execute(query, (flask_login.current_user.email, album_identifier, ))

    return cursor.fetchall()


def select_albums(cursor):

    query = """
        SELECT
            TRUE own_album,
            a.id id,
            a.identifier identifier,
            a.album_key_nonce album_key_nonce,
            a.data_nonce data_nonce,
            CAST(a.created AS INT) created,
            b.bucket_name,
            b.identifier bucket_identifier,
            a.album_bucket_prefix album_bucket_prefix,
            (IFNULL(SUM(f.bucket_size), 0) + IFNULL(SUM(ii.bucket_size), 0)) bucket_size,
            COUNT(f.id) count,
            CAST(MIN(f.file_date) AS INT) min_date,
            CAST(MAX(f.file_date) AS INT) max_date,
            u.public_key,
            "" shared_album_owner_email,
            0 shared_album_can_add_files,
            1 accepted,
            a.encrypted encrypted
        FROM
            album a
        JOIN
            bucket b ON a.bucket_id = b.id
        JOIN
            user_auth u ON u.id = %s
        LEFT OUTER JOIN
            album_file af ON a.id = af.album_id
        LEFT OUTER JOIN
            file f ON af.file_id = f.id AND f.deleted IS NULL
        LEFT OUTER JOIN
            index_info ii ON f.id = ii.file_id
        WHERE
            a.user_id = u.id
            /*AND f.bucket_size > 0*/
        GROUP BY
            a.id
    """

    cursor.execute(query, (flask_login.current_user.row_id, ))
    own_album_rows = cursor.fetchall()

    query = """
        SELECT
            FALSE own_album,
            a.id id,
            a.identifier identifier,
            sa.album_key_nonce album_key_nonce,
            a.data_nonce data_nonce,
            CAST(a.created AS INT) created,
            b.bucket_name,
            b.identifier bucket_identifier,
            a.album_bucket_prefix album_bucket_prefix,
            (IFNULL(SUM(f.bucket_size), 0) + IFNULL(SUM(ii.bucket_size), 0)) bucket_size,
            COUNT(f.id) count,
            CAST(MIN(f.file_date) AS INT) min_date,
            CAST(MAX(f.file_date) AS INT) max_date,
            u_from.public_key,
            u_from.email shared_album_owner_email,
            sa.accepted accepted,
            sa.can_add_files shared_album_can_add_files,
            a.encrypted encrypted
        FROM
            album a,
            user_auth u_from,
            shared_album sa,
            bucket b,
            album_file af,
            file f
        LEFT OUTER JOIN
            index_info ii ON ii.file_id = f.id
        WHERE
            sa.email_to = %s
            /*AND sa.accepted = 1*/
            AND sa.rejected = 0
            AND sa.album_id = a.id
            AND a.bucket_id = b.id
            AND af.album_id = a.id
            AND af.file_id = f.id
            AND u_from.id = a.user_id
            AND f.bucket_size > 0
            AND f.deleted IS NULL
        GROUP BY
            a.id
    """
    current_user = flask_login.current_user
    cursor.execute(query, (current_user.email, ))
    shared_album_rows = cursor.fetchall()

    if shared_album_rows and shared_album_rows[0].id is not None:
        return own_album_rows + shared_album_rows
    else:
        return own_album_rows


#def select_album_yyyymm_list(cursor, album_rowid):
#
#    if is_own_album(cursor, album_rowid=album_rowid):
#        query = """
#            SELECT
#                DISTINCT(CAST(f.file_date AS INT) DIV 100) as yyyymm
#            FROM
#                album_file af, file f
#            WHERE
#                f.user_id = %s
#                AND af.album_id = %s
#                AND af.file_id = f.id
#            ORDER BY
#                f.file_date
#        """
#        cursor.execute(query, (flask_login.current_user.row_id, album_rowid, ))
#    else:
#        query = """
#            SELECT
#                DISTINCT(CAST(f.file_date AS INT) DIV 100) as yyyymm
#            FROM
#                album_file af,
#                file f,
#                shared_album sa,
#                album a
#            WHERE
#                sa.email_to = %s
#                AND sa.album_id = a.id
#                AND sa.accepted = 1
#                AND sa.rejected = 0
#                AND sa.album_id = %s
#                AND f.user_id = a.user_id
#                AND af.album_id = sa.album_id
#                AND af.file_id = f.id
#            ORDER BY
#                f.file_date
#        """
#        current_user = flask_login.current_user
#        cursor.execute(query, (current_user.email, album_rowid, ))
#
#    return cursor.fetchall()


def select_album_active_day_list(cursor, album_identifier, year):

    if is_own_album(cursor, album_identifier=album_identifier):
        query = """
            SELECT
                DISTINCT(CAST(f.file_date AS INT)) as day
            FROM
                album a, album_file af, file f
            WHERE
                a.identifier = %s
                AND a.id = af.album_id
                AND f.user_id = %s
                AND af.file_id = f.id
                AND CAST(f.file_date AS INT) DIV 10000 = %s
                AND f.deleted IS NULL
            ORDER BY
                f.file_date
        """
        cursor.execute(query, (album_identifier, flask_login.current_user.row_id, year, ))
    else:
        query = """
            SELECT
                DISTINCT(CAST(f.file_date AS INT)) as day
            FROM
                album_file af,
                file f,
                shared_album sa,
                album a
            WHERE
                sa.email_to = %s
                AND a.identifier = %s
                AND sa.album_id = a.id
                AND sa.accepted = 1
                AND sa.rejected = 0
                AND f.user_id = a.user_id
                AND af.album_id = a.id
                AND af.file_id = f.id
                AND CAST(f.file_date AS INT) DIV 10000 = %s
                AND f.deleted IS NULL
            ORDER BY
                f.file_date
        """
        current_user = flask_login.current_user
        cursor.execute(query, (current_user.email, album_identifier, year, ))

    return cursor.fetchall()


def select_album_identifiers_by_bucket_identifier(cursor, bucket_identifier):
    query = """
        SELECT
            a.identifier identifier
        FROM
            album a,
            bucket b
        WHERE
            a.user_id = %s
            AND b.user_id = a.user_id
            AND a.bucket_id = b.id
            AND b.identifier = %s
    """
    cursor.execute(query, (flask_login.current_user.row_id, bucket_identifier, ))
    return cursor.fetchall()

def select_own_album_identifier_by_file_identifier(cursor, file_identifier):
    query = """
        SELECT
            a.identifier identifier
        FROM
            album a,
            album_file af,
            file f
        WHERE
            a.user_id = %s
            AND a.id = af.album_id
            AND af.file_id = f.id
            AND f.identifier = %s
            AND f.deleted IS NULL
    """
    cursor.execute(query, (flask_login.current_user.row_id, file_identifier, ))
    return cursor.fetchall()

def select_album_identifier_by_file_identifier(cursor, file_identifier):
    query = """
        SELECT
            a.identifier identifier
        FROM
            album a,
            album_file af,
            file f
        WHERE
            a.id = af.album_id
            AND af.file_id = f.id
            AND f.identifier = %s
            AND f.deleted IS NULL
    """
    cursor.execute(query, (file_identifier, ))
    return cursor.fetchall()


def select_album_files_at_or_before_date(cursor, album_rowid, yyyymmdd):

    if is_own_album(cursor, album_rowid=album_rowid):
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                1 can_edit_file,
                1 can_delete_file
            FROM
                file f,
                album_file af
            WHERE
                af.album_id = %s
                AND af.file_id = f.id
                AND f.user_id = %s
                AND CAST(f.file_date AS INT) <= %s
                AND f.deleted IS NULL
            ORDER BY
                f.file_date DESC, f.ordering
            LIMIT 25
        """
        cursor.execute(query, (album_rowid, flask_login.current_user.row_id, yyyymmdd))
    else:
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                IF(f.creator_id = %s && sa.can_add_files = 1, 1, 0) can_edit_file,
                0 can_delete_file
            FROM
                file f,
                album_file af,
                shared_album sa,
                album a
            WHERE
                af.album_id = %s
                AND sa.email_to = %s
                AND sa.accepted = 1
                AND sa.rejected = 0
                AND sa.album_id = af.album_id
                AND af.file_id = f.id
                AND a.id = sa.album_id
                AND f.user_id = a.user_id
                AND CAST(f.file_date AS INT) <= %s
                AND f.deleted IS NULL
            ORDER BY
                f.file_date DESC, f.ordering
            LIMIT 25
        """
        current_user = flask_login.current_user
        cursor.execute(query, (current_user.row_id, album_rowid, current_user.email, yyyymmdd))

    return cursor.fetchall()

def select_album_files_newer_than_file_id(cursor, album_rowid, file_id):

    current_user = flask_login.current_user

    if is_own_album(cursor, album_rowid=album_rowid):
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                1 can_edit_file,
                1 can_delete_file
            FROM
                file f,
                file start_f,
                album_file af,
                album_file start_af
            WHERE
                af.album_id = %s
                AND af.file_id = f.id
                AND f.user_id = %s
                AND start_af.album_id = af.album_id
                AND start_af.file_id = start_f.id
                AND start_f.identifier = %s
                AND (
                    CAST(f.file_date AS INT) > CAST(start_f.file_date AS INT)
                    OR
                    CAST(f.file_date AS INT) = CAST(start_f.file_date AS INT)
                    AND f.ordering < start_f.ordering
                )
                AND f.deleted IS NULL
            ORDER BY
                f.file_date, f.ordering DESC
            LIMIT 25
        """
        cursor.execute(query, (album_rowid, current_user.row_id, file_id))
    else:
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                IF(f.creator_id = %s && sa.can_add_files = 1, 1, 0) can_edit_file,
                0 can_delete_file
            FROM
                file f,
                album_file af,
                shared_album sa,
                album a,
                file start_f,
                album_file start_af
            WHERE
                af.album_id = %s
                AND sa.email_to = %s
                AND sa.accepted = 1
                AND sa.rejected = 0
                AND sa.album_id = af.album_id
                AND af.file_id = f.id
                AND a.id = sa.album_id
                AND f.user_id = a.user_id
                AND start_af.album_id = af.album_id
                AND start_af.file_id = start_f.id
                AND start_f.identifier = %s
                AND (
                    CAST(f.file_date AS INT) > CAST(start_f.file_date AS INT)
                    OR
                    CAST(f.file_date AS INT) = CAST(start_f.file_date AS INT)
                    AND f.ordering < start_f.ordering
                )
                AND f.deleted IS NULL
            ORDER BY
                f.file_date, f.ordering DESC
            LIMIT 25
        """
        cursor.execute(query, (current_user.row_id, album_rowid, current_user.email, file_id))

    return cursor.fetchall()

def select_album_files_older_than_file_id(cursor, album_rowid, file_id):

    current_user = flask_login.current_user

    if is_own_album(cursor, album_rowid=album_rowid):
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                1 can_edit_file,
                1 can_delete_file
            FROM
                file f,
                file start_f,
                album_file af,
                album_file start_af
            WHERE
                af.album_id = %s
                AND af.file_id = f.id
                AND f.user_id = %s
                AND start_af.album_id = af.album_id
                AND start_af.file_id = start_f.id
                AND start_f.identifier = %s
                AND (
                    CAST(f.file_date AS INT) < CAST(start_f.file_date AS INT)
                    OR
                    CAST(f.file_date AS INT) = CAST(start_f.file_date AS INT)
                    AND f.ordering > start_f.ordering
                )
                AND f.deleted IS NULL
            ORDER BY
                f.file_date DESC, f.ordering
            LIMIT 25
        """
        cursor.execute(query, (album_rowid, current_user.row_id, file_id))
    else:
        query = """
            SELECT
                f.identifier identifier,
                f.data_nonce data_nonce,
                CAST(f.file_date AS INT) file_date,
                f.ordering file_ordering,
                af.file_key_nonce file_key_nonce,
                f.comment comment,
                f.bucket_size bucket_size,
                IF(f.creator_id = %s && sa.can_add_files = 1, 1, 0) can_edit_file,
                0 can_delete_file
            FROM
                file f,
                album_file af,
                shared_album sa,
                album a,
                file start_f,
                album_file start_af
            WHERE
                af.album_id = %s
                AND sa.email_to = %s
                AND sa.accepted = 1
                AND sa.rejected = 0
                AND sa.album_id = af.album_id
                AND af.file_id = f.id
                AND a.id = sa.album_id
                AND f.user_id = a.user_id
                AND start_af.album_id = af.album_id
                AND start_af.file_id = start_f.id
                AND start_f.identifier = %s
                AND (
                    CAST(f.file_date AS INT) < CAST(start_f.file_date AS INT)
                    OR
                    CAST(f.file_date AS INT) = CAST(start_f.file_date AS INT)
                    AND f.ordering > start_f.ordering
                )
                AND f.deleted IS NULL
            ORDER BY
                f.file_date DESC, f.ordering
            LIMIT 25
        """
        cursor.execute(query, (current_user.row_id, album_rowid, current_user.email, file_id))

    return cursor.fetchall()

# used to be called select_user_total_system_bucket_size
def select_user_total_system_bucket_used_space_bytes(cursor):
    query = """
        SELECT
            SUM(f.bucket_size) + SUM(ii.bucket_size) sum
        FROM
            file f
        JOIN
            album_file af ON f.id = af.file_id
        JOIN
            album a ON af.album_id = a.id
        JOIN
            bucket b ON a.bucket_id = b.id
        LEFT OUTER JOIN
            index_info ii ON f.id = ii.file_id
        WHERE
            b.user_id = %s
            AND b.is_system = 1
            AND f.deleted IS NULL
    """
    cursor.execute(query, (flask_login.current_user.row_id, ))
    rows = cursor.fetchall()

    if not rows:
        return 0

    total_sz = rows[0].sum
    return 0 if not total_sz else total_sz

def select_download_auth_cache_for_album(cursor, album_identifier):
    query = """
        SELECT
            c.expires expires,
            c.url url,
            c.auth auth
        FROM
            download_auth_cache c,
            album a,
            user_auth u
        WHERE
            u.id = %s
            AND a.identifier = %s
            AND a.user_id = u.id
            AND c.bucket_id = a.bucket_id
            AND c.album_id = a.id
            AND c.expires > UNIX_TIMESTAMP(CURRENT_TIMESTAMP() + INTERVAL 10 MINUTE)
        ORDER BY
            c.expires DESC
        LIMIT 1
    """
    cursor.execute(query, (flask_login.current_user.row_id, album_identifier))
    return cursor.fetchall()

def insert_download_auth_cache_for_album(cursor, bucket_id, album_id, url, auth, expires):
    query = """
        INSERT INTO
            download_auth_cache (bucket_id, album_id, expires, url, auth)
        VALUES
            (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (bucket_id, album_id, expires, url, auth))
    return cursor.lastrowid


# def delete_file(c, file_identifier):
#     query = """
#         DELETE
#             af, f
#         FROM
#             album_file af, file f
#         WHERE
#             f.user_id = %s
#             AND f.identifier = %s
#             AND af.file_id = f.id
#         """

#     c.execute(query, (flask_login.current_user.row_id, file_identifier))
#     return c.rowcount

def select_index_info(cursor, file_identifier):
    query = """
        SELECT
            ii.data_nonce data_nonce,
            ii.bucket_size bucket_size
        FROM
            index_info ii,
            file f
        WHERE
            ii.file_id = f.id
            AND f.identifier = %s
            AND f.user_id = %s
        UNION ALL
        SELECT
            ii.data_nonce data_nonce,
            ii.bucket_size bucket_size
        FROM
            user_auth u,
            shared_album sa,
            album_file af,
            index_info ii,
            file f
        WHERE
            u.id = %s
            AND sa.email_to = u.email
            AND sa.album_id = af.album_id
            AND af.file_id = f.id
            AND f.identifier = %s
            AND ii.file_id = f.id
            AND f.deleted IS NULL
    """
    cursor.execute(query, (file_identifier, flask_login.current_user.row_id,
        flask_login.current_user.row_id, file_identifier))
    return cursor.fetchall()

# def delete_index_info(cursor, file_identifier):
#     query = """
#         DELETE
#             ii
#         FROM
#             file f,
#             index_info ii
#         WHERE
#             f.user_id = %s
#             AND f.identifier = %s
#             AND ii.file_id = f.id
#         """

#     cursor.execute(query, (flask_login.current_user.row_id, file_identifier))
#     return cursor.rowcount


def insert_user_trx_history_record(cursor, action, details):
    query = """
        INSERT INTO
            user_transaction_history (user_id, action, details)
        VALUES
            (%s, %s, %s)
    """

    user_id = 0 if flask_login.current_user.is_anonymous else flask_login.current_user.row_id
    cursor.execute(query, (user_id, action, details, ))
    return cursor.rowcount

def response_from_pack(pack):
    resp = flask.make_response(bytes(pack))
    resp.headers['Content-Type'] = 'application/octet-stream'
    return resp

@login_manager.user_loader
def load_user(email):
    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        return select_user(cursor, email)

@apiv1_blueprint.route('/api/v1/login', methods=['POST'])
@lib.errors.exception_wrapper
def user_login():

    unpack = lib.packer.unpack_value(request.data)

    user_data = unpack['user']
    email = user_data['email'].lower()
    entered_password = user_data['auth']

    flask.session['uid'] = uuid.uuid4().hex

    callid = log.new_callid()
    log.webapi(log.API_CALL_LOGIN, {"cid": callid, "email": email})

    user = load_user(email)

    if user is None:
        log.webapi(log.API_CALL_LOGIN_ERROR, {"cid": callid, "error": 400})
        return '', 400

    if user.delete_timestamp is not None:
        log.webapi(log.API_CALL_LOGIN_ERROR, {"cid": callid, "error": 405})
        return '', 405 # method not allowed

    if user.row_id > 62:
        entered_password = base64.b64encode(entered_password)

    is_password_ok = bcrypt.checkpw(entered_password, user.hashed)

    if is_password_ok:
        flask_login.login_user(user, remember=True)

        pack = lib.packer.pack_value({
            'user': {
                'public_key': user.public_key,
                'encrypted_private_key': user.encrypted_private_key,
                'default_album_ident': user.default_album,
                'default_bucket_ident': user.default_bucket,
                'subscription_status': user.subscription_status,
                'email_confirmed': user.email_confirmed,
                'subscription_end': user.stripe_current_period_end,
                'max_storage_gb': user.max_storage_gb,
                'account_type': user.account_type,
            },
        })

        log.webapi(log.API_CALL_LOGIN_OK, {"cid": callid})
        resp = flask.make_response(response_from_pack(pack), 200)
        resp.set_cookie('RK', random_string())
        return resp
    else:
        log.webapi(log.API_CALL_LOGIN_ERROR, {"cid": callid, "error": 401})
        return '', 401

# TODO: salt from env
def build_session_hash():
    m = hashlib.sha256()
    m.update(bytes(request.cookies['RK'], 'ascii'))
    return m.hexdigest()

def get_session_data(cursor):
    query = """
        SELECT
            data, expires
        FROM
            session
        WHERE
            session_hash = %s
            AND expires > CURRENT_TIMESTAMP
    """
    session_hash = build_session_hash()

    cursor.execute(query, (session_hash, ))
    rows = cursor.fetchall()
    if not rows:
        return {}

    return lib.packer.unpack_value(rows[0].data)

def set_session_data(cursor, data):

    query = """
        REPLACE INTO
            session (session_hash, data, expires)
        VALUES
            (%s, %s, CURRENT_TIMESTAMP + INTERVAL 15 DAY)
    """
    session_hash = build_session_hash()
    data = lib.packer.pack_value(data)
    cursor.execute(query, (session_hash, data))


@apiv1_blueprint.route('/api/v1/recall', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_get_recall():

    # Here's the story: since the app doesn't store user passwords on
    # server, the user needs to re-login after every page refresh. To save
    # some logins, the app stores user keys in browser local storage (should it be
    # optional and/or time-limited?). To protect data in the local storage it's
    # encrypted with user+session-dependent temporary password stored in server
    # process and returned by this API call

    # the digest, which is used as a symmetric key by client, is built as SHA256 hash of
    # - a randomly generated 16-byte sequence (see api_set_recall())
    # - 'RK' value: a randomly generated cookie send to client at /login time

    # 'remember_token' is a cookie set by flask-login
    # (the name is set via flask_login.COOKIE_NAME global var)

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETRECALL, {"cid": callid})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        session_data = get_session_data(cursor)
        if 'recall_digest_key' not in session_data:
            log.webapi(log.API_CALL_GETRECALL_EMPTY, {"cid": callid})
            return response_from_pack(lib.packer.pack_value({"recall_digest": ""}))

        recall_digest = build_recall_digest(session_data['recall_digest_key'],
            bytes(request.cookies['RK'], 'ascii'))

        user = flask_login.current_user

        pack = lib.packer.pack_value({
            "recall_digest": recall_digest,
            "account_type": user.account_type,
            "default_album_ident": user.default_album,
            "default_bucket_ident": user.default_bucket,
            "subscription_status": user.subscription_status,
            "email_confirmed": user.email_confirmed,
            "subscription_end": user.stripe_current_period_end,
            "max_storage_gb": user.max_storage_gb,
        })
        log.webapi(log.API_CALL_GETRECALL_EXISTS, {"cid": callid})
        return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/recall', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_set_recall():

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTRECALL, {"cid": callid})

    # During login, the remember_token cookie is not available yet,
    # so the client makes a separate async call with the cookie set

    with lib.database.connect() as conn:
        recall_digest_key = secrets.token_bytes(16)
        cursor = lib.database.get_cursor(conn)

        session_data = get_session_data(cursor)
        session_data['recall_digest_key'] = recall_digest_key
        set_session_data(cursor, session_data)
        conn.commit()

    recall_digest = build_recall_digest(recall_digest_key,
        bytes(request.cookies['RK'], 'ascii'))

    pack = lib.packer.pack_value({"recall_digest": recall_digest})
    log.webapi(log.API_CALL_POSTRECALL_OK, {"cid": callid})
    return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/user-public-key', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_get_user_public_key():
    """
    user requests public keys of other users to share albums with them
    """

    email = unquote(request.args.get('email')).lower()

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETPUBKEY, {"cid": callid, "email": email})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        public_key = select_user_public_key(cursor, email)
        pack = lib.packer.pack_value({"public_key": public_key if public_key else ""})
        log.webapi(log.API_CALL_GETPUBKEY_OK, {
            "cid": callid, "keylength": 0 if public_key is None else len(public_key)})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/logout', methods=['POST'])
@lib.errors.exception_wrapper
#@flask_login.login_required
def api_logout():

    email = flask_login.current_user.email
    flask_login.logout_user()

    callid = log.new_callid()
    log.webapi(log.API_CALL_LOGOUT, {"cid": callid, "email": email})

    del flask.session['uid']

    return '', 200


@apiv1_blueprint.route('/api/v1/upgrade-account', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_upgrade_account():

    callid = log.new_callid()
    log.webapi(log.API_CALL_UPGRADE_ACCOUNT, {"cid": callid})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            UPDATE
                user_auth
            SET
                account_type = %s,
                max_storage_gb = %s
            WHERE
                id = %s
        """

        cursor.execute(query, (
            ACCOUNT_TYPE_STANDARD,
            1,
            flask_login.current_user.row_id,
        ))

        conn.commit()

        log.webapi(log.API_CALL_UPGRADE_ACCOUNT_OK, {
            "cid": callid,
            "old_account_type": flask_login.current_user.account_type,
            "new_account_type": ACCOUNT_TYPE_STANDARD,
            "max_storage_gb": 1,
        })

    flask_login.current_user.account_type = ACCOUNT_TYPE_STANDARD
    flask_login.current_user.max_storage_gb = 1


    return response_from_pack(lib.packer.pack_value({
        "account_type": ACCOUNT_TYPE_STANDARD,
        "max_storage_gb": 1,
    })), 200



@apiv1_blueprint.route('/api/v1/guests', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_guests_get():
    """
    guests are users this user shares albums with
    """

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETGUESTS, {"cid": callid})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        rows = select_guests(cursor)

        guest_list = [row.email for row in rows]

        pack = lib.packer.pack_value({
            'guests': guest_list,
        })

        log.webapi(log.API_CALL_GETGUESTS_OK, {"cid": callid,
            "guest_list_len": len(guest_list)})

        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/invite', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_invite():

    pack = lib.packer.unpack_value(request.data)
    email_to = pack['email_to'].lower()

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTINVITE, {"cid": callid})

    # cannot "share" with self
    if email_to == flask_login.current_user.email:
        log.webapi(log.API_CALL_POSTINVITE_ERROR, {"cid": callid, "error": 400, "point": 1})
        return '', 400

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        #can_share = select_user_can_share_albums(cursor)
        #if not can_share:
        #    return '', 429 # too many requests

        # check if user with this email exists
        user_to = select_user(cursor, email_to)
        if user_to is None:
            # user doesn't exist, send email invitation
            can_send = can_send_email_to(cursor, email_to)
            if can_send:
                resp = lib.mail.send_invitation(email_to)

        if resp.status_code == 200:
            log.webapi(log.API_CALL_POSTINVITE_OK, {"cid": callid})
            return '', 200
        else:
            log.webapi(log.API_CALL_POSTINVITE_ERROR,
                {"cid": callid, "status": resp.status_code, "point": 2})
            return '', 400


@apiv1_blueprint.route('/api/v1/share-album', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_share_album():

    pack = lib.packer.unpack_value(request.data)
    encrypted_album_key = pack['encrypted_album_key']
    album_identifier = pack['album_identifier']
    can_add_files = pack['allow_add_files']
    email_to = pack['email_to'].lower()

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTSHAREALBUM, {"cid": callid, "email": email_to})

    # cannot "share" with self
    if email_to == flask_login.current_user.email:
        log.webapi(log.API_CALL_POSTSHAREALBUM_ERROR,
            {"cid": callid, "error": 400, "point": 1})
        return '', 400

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        can_share = select_user_can_share_albums(cursor)
        if not can_share:
            log.webapi(log.API_CALL_POSTSHAREALBUM_ERROR, {"cid": callid, "error": 429})
            return '', 429 # too many requests

        own_album = is_own_album(cursor, album_identifier=album_identifier)
        if not own_album:
            log.webapi(log.API_CALL_POSTSHAREALBUM_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        shared_rows = select_shared_album(cursor, album_identifier, email_to)
        if len(shared_rows) > 0:
            if len(shared_rows[0].album_key_nonce) == 0:
                update_shared_album_key(
                    cursor, album_identifier, email_to, encrypted_album_key)
                conn.commit()
            log.webapi(log.API_CALL_POSTSHAREALBUM_OK, {"cid": callid, "dupshare": 1})
            return '', 200


        # check if user with this email exists
        user_to = select_user(cursor, email_to)
        if user_to is None:
            log.webapi(log.API_CALL_POSTSHAREALBUM_ERROR,
                {"cid": callid, "email": email_to, "point": 3})
            return '', 400
        #if user_to is None:
        #    # user doesn't exist, send email invitation
        #    can_send = can_send_email_to(cursor, email_to)
        #    if can_send:
        #        lib.mail.send_invitation(email_to)

        insert_shared_album(cursor, email_to, can_add_files,
            album_identifier, encrypted_album_key)
        conn.commit()
        return '', 200


@apiv1_blueprint.route('/api/v1/share-album', methods=['DELETE'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_delete_shared_album():

    album_identifier = request.args.get("album")
    email_to = request.args.get("email").lower()

    callid = log.new_callid()
    log.webapi(log.API_CALL_DELETESHAREDALBUM, {"cid": callid,
        "email": email_to, "album": album_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        own_album = is_own_album(cursor, album_identifier=album_identifier)
        if not own_album:

            log.webapi(log.API_CALL_DELETESHAREDALBUM_ERROR, {"cid": callid, "error": 400})
            return 400, ""

        delete_shared_album(cursor, album_identifier, email_to)
        conn.commit()
        log.webapi(log.API_CALL_DELETESHAREDALBUM_OK, {"cid": callid})
        return '', 200


@apiv1_blueprint.route('/api/v1/respond-share-album', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_respond_share_album():

    pack = lib.packer.unpack_value(request.data)
    album_identifier = pack['album_identifier']
    response = pack['response']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTRESPONDSHAREDALBUM, {"cid": callid,
        "album": album_identifier, "response": response})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        if response == "accept":
            update_shared_album_status(cursor, album_identifier, accepted=1, rejected=0)
            conn.commit()
            log.webapi(log.API_CALL_POSTRESPONDSHAREDALBUM_OK, {"cid": callid})
            return '', 200

        if response == "reject":
            update_shared_album_status(cursor, album_identifier, accepted=0, rejected=1)
            conn.commit()
            log.webapi(log.API_CALL_POSTRESPONDSHAREDALBUM_OK, {"cid": callid})
            return '', 200

        if response == "block":
            update_shared_album_status(cursor, album_identifier, accepted=0, rejected=1);
            insert_block_user_by_shared_album(cursor, album_identifier)
            conn.commit()
            log.webapi(log.API_CALL_POSTRESPONDSHAREDALBUM_OK, {"cid": callid})
            return '', 200

        log.webapi(log.API_CALL_POSTRESPONDSHAREDALBUM_ERROR, {"cid": callid, "error": 400})
        return '', 400

# handler of presigned requests
@apiv1_blueprint.route('/r/<jwt_token>', methods=['GET'])
@lib.errors.exception_wrapper
def api_invite_jwt_response(jwt_token):

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETJWTRESPONSE, {"cid": callid})

    token = lib.simplejwt.decode_jwt(jwt_token)
    request = token['request']

    if request == 'invite':
        email_from = token['from'].lower()
        email_to = token['to'].lower()
        timestamp = token['timestamp']

        log.webapi(log.API_CALL_GETJWTRESPONSE, {"cid": callid,
            "email_from": email_from, "email_to": email_to,
            "timestamp": timestamp, "response": token['response']})

        # TODO: expiration?
        with lib.database.connect() as conn:
            cursor = lib.database.get_cursor(conn)
            if token['response'] == 'accept':
                #try:
                #    insert_invite_request_without_login(cursor,
                #        email_from, email_to, confirmed=1, blocked=0)
                #    conn.commit()
                #except mariadb.IntegrityError:
                #    pass # user is probably clicking the link multiple times

                log.webapi(log.API_CALL_GETJWTRESPONSE_OK, {"cid": callid,
                    "redirect": "/signup/"})

                return redirect('/signup/' + quote(email_to), code=303)
            else:
                #insert_invite_request_without_login(cursor,
                #    email_from, email_to, confirmed=0, blocked=1)
                #conn.commit()

                log.webapi(log.API_CALL_GETJWTRESPONSE_OK, {"cid": callid})
                return '', 200 # TODO: confirmation message
    elif request == "email-confirmation":

        email_to = token['to'].lower()
        code = token['code']
        timestamp = token['timestamp']

        log.webapi(log.API_CALL_GETJWTRESPONSE, {"cid": callid,
            "email_to": email_to, "timestamp": timestamp, "code": code})

        with lib.database.connect() as conn:
            cursor = lib.database.get_cursor(conn)
            query = """SELECT email_confirmed FROM user_auth WHERE email = %s"""
            cursor.execute(query, (email_to, ))
            rows = cursor.fetchall()
            if len(rows) != 1 or rows[0].email_confirmed not in ["1", code]:
                return '', 400
            query = """UPDATE user_auth SET email_confirmed = '1' WHERE email = %s"""
            cursor.execute(query, (email_to, ))
            conn.commit()

            return redirect('/login', code=303)

    else:
        log.webapi(log.API_CALL_GETJWTRESPONSE_ERROR, {"cid": callid, "error": 401})
        return '', 401


@apiv1_blueprint.route('/api/v1/user', methods=['POST'])
@lib.errors.exception_wrapper
def api_user_create():

    pack = lib.packer.unpack_value(request.data)
    user_data = pack['user']
    account_type = user_data['account_type']
    email = user_data['email'].decode('utf8').lower()
    #email_code = user_data['email_code']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTUSER, {"cid": callid, "email": email, "account_type": account_type, })

    if '@' not in email:
        log.webapi(log.API_CALL_POSTUSER_ERROR,
            {"cid": callid, "reason": "invalid email address"})
        return '', 400

    # may be pre-filled below from the account_application_registry table
    email_confirmation_code = None

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        # check if this user previously disabled all communications
        can_send = can_send_email_to(cursor, email)
        if not can_send:
            log.webapi(log.API_CALL_POSTUSER_ERROR,
                {"cid": callid, "reason": "user disabled comms"})
            return '', 400

        # cursor.execute("""
        #     SELECT email_code FROM account_application_registry WHERE email = %s AND registration_enabled = TRUE
        #     """, (email, ))

        # rows = cursor.fetchall()

        # if len(rows) == 0:
        #     log.webapi(log.API_CALL_POSTUSER_ERROR,
        #         {"cid": callid, "reason": f"registration not enabled for ${email}"})
        #     return '', 400

        # email_confirmation_code = rows[0].email_code

    #request_email_confirmation_code = email_confirmation_code != email_code
    request_email_confirmation_code = True

    auth_hash = user_data['auth']
    encrypted = 1 # TODO: this should come from signup defaults

    if flask_login.current_user.is_authenticated:
        logged_out = flask_login.logout_user()
        if not logged_out:
            log.webapi(log.API_CALL_POSTUSER_ERROR,
                {"cid": callid, "error": 500, "reason": "logout failed"})
            return '', 500

    encrypted_private_key = user_data['encrypted_private_key']
    public_key = user_data['public_key']

    if load_user(email) is not None:
        log.webapi(log.API_CALL_POSTUSER_ERROR, {"cid": callid, "error": 409})
        return '', 409 # Conflict

    # hashpw doesn't like NUL-bytes, so convert to base64
    auth_hash = bcrypt.hashpw(base64.b64encode(auth_hash), bcrypt.gensalt())

    if account_type == ACCOUNT_TYPE_STANDARD:
        album_data = pack['album']
        encrypted_album_key = album_data['encrypted_album_key']
        encrypted_album_data = album_data['encrypted_album_data']

        album_identifier = 'alb' + secrets.token_hex(16)

    bucket_identifier = 'bkt' + secrets.token_hex(16)
    album_bucket_prefix = "pfx" + secrets.token_hex(16)

    test_infix1 = app.config['MEDIASERVICE_TEST_EMAIL_INFIX1']
    test_infix2 = app.config['MEDIASERVICE_TEST_EMAIL_INFIX2']
    replacement_email = app.config['MEDIASERVICE_TEST_EMAIL_REPLACEMENT']

    if request_email_confirmation_code:
        email_confirmation_code = get_email_confirmation_code(email)

    b2_client = lib.b2.Client()
    b2_client.authorize_account(
        app.config['MEDIASERVICE_B2_KEYID'],
        app.config['MEDIASERVICE_B2_KEY'])

    # create stripe customer
    if ENABLE_STRIPE:
        try:
            stripe_customer = stripe.Customer.create(email=email)
            stripe_customer_id = stripe_customer['id']
        except Exception as e:
            log.webapi(log.API_CALL_POSTUSER_ERROR,
                {"cid": callid, "email": email, "point": "stripe", "error": str(e)})
            return '', 400
    else:
        stripe_customer_id = ""

    # insert user, init b2
    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        #default_album_ident = album_identifier
        default_album_ident = "most-recently-updated"

        insert_user(
            cursor,
            email,
            email_confirmation_code if request_email_confirmation_code else "1",
            account_type,
            auth_hash,
            encrypted_private_key,
            public_key,
            default_album_ident if account_type == ACCOUNT_TYPE_STANDARD else "most-recently-updated",
            bucket_identifier,
            stripe_customer_id)

        user = select_user(cursor, email)

        if not user:
            log.webapi(log.API_CALL_POSTUSER_ERROR, {"cid": callid, "error": 500, "point": 1})
            return '', 500

        bucket_service = "backblaze-b2"
        bucket_bucketid = app.config['MEDIASERVICE_B2_BUCKETID']
        bucket_name = app.config['MEDIASERVICE_B2_BUCKETNAME']

        # TODO: check that prefix doesn't exist

        album_bucket_key_id, album_bucket_key = \
            b2_client.create_key_for_prefix(bucket_bucketid, album_bucket_prefix)

        bucket_id = insert_bucket(
            cursor,
            user.row_id,
            bucket_identifier,
            bucket_service,
            bucket_bucketid,
            bucket_name)

        encrypted_album_bucket_key = adminapi.encrypt_bucket_key(album_bucket_key)

        if encrypted_album_bucket_key is None:
            log.webapi(
              log.API_CALL_POSTUSER_ERROR,
              {"cid": callid, "error": 500, "point": "encrypt_bucket_key failed"},
            )
            return '', 500

        if account_type == ACCOUNT_TYPE_STANDARD:
              insert_album(
                cursor,
                user.row_id,
                bucket_id,
                album_identifier,
                encrypted_album_key,
                encrypted_album_data,
                album_bucket_prefix,
                album_bucket_key_id,
                encrypted,
                encrypted_album_bucket_key,
              )

        confirmation_email_ok = False

        if request_email_confirmation_code:
            if test_infix1 in email:
                confirmation_email_ok = True
            else:
                send_email_address = replacement_email if test_infix2 in email else email
                for x in range(2):
                    resp = lib.mail.send_email_confirmation_request(
                        send_email_address,
                        email_confirmation_code )
                    log.webapi(log.API_CALL_POSTUSER,
                        {"cid": callid, "conf-email-status": resp.status_code})
                    if resp.status_code == 200:
                        confirmation_email_ok = True
                        break
        else:
            confirmation_email_ok = True

        if not confirmation_email_ok:
            log.webapi(log.API_CALL_POSTUSER_ERROR, {"cid": callid, "error": 500, "point": "email"})
            return '', 500
        else:
            # only commit to the database if email was successfully sent
            conn.commit()


    # user will be redirected to login
    log.webapi(log.API_CALL_POSTUSER_OK, {"cid": callid})
    return '', 200


# apply for account (restricted registration)
@apiv1_blueprint.route('/api/v1/apply', methods=['POST'])
@lib.errors.exception_wrapper
def api_user_apply():

    pack = lib.packer.unpack_value(request.data)
    email = pack['email'].decode('utf8').lower()

    callid = log.new_callid()
    log.webapi(log.API_CALL_APPLY, {"cid": callid, "email": email})

    if '@' not in email:
        log.webapi(log.API_CALL_APPLY_ERROR,
            {"cid": callid, "reason": "invalid email address"})
        return '', 400

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        # check if this user previously disabled all communications
        can_send = can_send_email_to(cursor, email)
        if not can_send:
            log.webapi(log.API_CALL_APPLY_ERROR,
                {"cid": callid, "reason": "user disabled comms"})

    if flask_login.current_user.is_authenticated:
        logged_out = flask_login.logout_user()
        if not logged_out:
            log.webapi(log.API_CALL_APPLY_ERROR,
                {"cid": callid, "error": 500, "reason": "logout failed"})
            return '', 500

    email_confirmation_code = get_email_confirmation_code(email)

    # insert user, init b2
    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            INSERT IGNORE INTO account_application_registry (email, email_code, registration_enabled) VALUES (%s, %s, %s)
        """

        cursor.execute(query, (
            email,
            email_confirmation_code,
            True,
        ))
        conn.commit()


    # user will be redirected to login
    log.webapi(log.API_CALL_APPLY_OK, {"cid": callid})
    return '', 200

@apiv1_blueprint.route('/api/v1/subscription', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
def checkout_session_create():

    callid = log.new_callid()
    log.webapi(log.API_CALL_SUBSCRIPTION, {"cid": callid})

    form_subscription = request.form['subscription']
    form_price = request.form['price']

    log.webapi(log.API_CALL_SUBSCRIPTION,
        {"cid": callid, "sub": form_subscription, "price": form_price})

    if ENABLE_STRIPE:
        subscription_data = None

        if form_subscription == "standard":
            if form_price == "5":
                price = app.config['STRIPE_PRICE_100G']
            elif form_price == "10":
                price = app.config['STRIPE_PRICE_1T']
            elif form_price == "20":
                price = app.config['STRIPE_PRICE_2T']
            elif form_price == "50":
                price = app.config['STRIPE_PRICE_5T']
            elif form_price == "100":
                price = app.config['STRIPE_PRICE_10T']
            else:
                log.webapi(log.API_CALL_SUBSCRIPTION_ERROR,
                    {"cid": callid, "point": 1})
                return '', 400
        elif form_subscription == "viewer":
            with lib.database.connect() as conn:
                cursor = lib.database.get_cursor(conn)

                query = """
                    UPDATE
                        user_auth
                    SET
                        stripe_subscription_id = '',
                        subscription_status = %s,
                        stripe_current_period_end = CURRENT_TIMESTAMP,
                        max_storage_gb = 0
                    WHERE
                        id = %s
                """

                cursor.execute(query, (
                    SUBSCRIPTION_STATUS_VIEWER, flask_login.current_user.row_id, ))
                conn.commit()
            return redirect('/sub/status', code=303)

        elif form_subscription == "trial":
            #price = app.config['STRIPE_PRICE_100G']
            #subscription_data = {
            #    'trial_period_days': 14,
            #}

            with lib.database.connect() as conn:
                cursor = lib.database.get_cursor(conn)

                query = """
                    UPDATE
                        user_auth
                    SET
                        stripe_subscription_id = '',
                        subscription_status = %s,
                        stripe_current_period_end = CURRENT_TIMESTAMP + INTERVAL 14 DAY,
                        max_storage_gb = 1
                    WHERE
                        id = %s
                """

                cursor.execute(query, (
                    SUBSCRIPTION_STATUS_TRIAL, flask_login.current_user.row_id, ))

                conn.commit()
            return redirect('/sub/status', code=303)

        else:
            log.webapi(log.API_CALL_SUBSCRIPTION_ERROR,
                {"cid": callid, "point": 2})
            return '', 400

        base_url = app.config['STRIPE_WEBHOOK_BASEURL']

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price,
                'quantity': 1,
            }],
            metadata={
                "cid": str(callid),
            },
            mode='subscription',
            subscription_data=subscription_data,
            customer=flask_login.current_user.stripe_customer_id,
            success_url=base_url+'/sub/status',
            cancel_url=base_url+ '/sub/status',
        )

        log.webapi(log.API_CALL_SUBSCRIPTION_OK, {"cid": callid})
    else: # not ENABLE_STRIPE
        with lib.database.connect() as conn:
            cursor = lib.database.get_cursor(conn)

            query = """
                UPDATE
                    user_auth
                SET
                    stripe_subscription_id = '',
                    subscription_status = %s,
                    stripe_current_period_end = 0,
                    max_storage_gb = IF(account_type = %s, 0, 1)
                WHERE
                    id = %s
            """

            cursor.execute(query, (
                SUBSCRIPTION_STATUS_PAID,
                ACCOUNT_TYPE_FREE,
                flask_login.current_user.row_id, ))

            conn.commit()
            log.webapi(log.API_CALL_SUBSCRIPTION_OK,
                {"cid": callid, "point": "stripe-disabled"})

        return redirect("/login", code=303)


    return redirect(session.url, code=303)

@apiv1_blueprint.route('/api/v1/stripe-webhook', methods=['GET', 'POST'])
@lib.errors.exception_wrapper
def stripe_webhook():

    callid = log.new_callid()
    log.webapi(log.API_CALL_STRIPEWEBHOOK, {"cid": callid})

    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    signature = request.headers.get('stripe-signature')

    event = stripe.Webhook.construct_event(
        payload=request.data, sig_header=signature, secret=webhook_secret)
    data = event['data']

    event_type = event['type']
    event_id = event['id']

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        insert_user_trx_history_record(cursor,
            event_type, json.dumps({"id": event_id, }))

        #if event_type == 'checkout.session.completed':
        #    # first payment success

        #    stripe_customer_id = data['object']['customer']
        #    stripe_subscription_id = data['object']['subscription']

        #    query = """
        #        UPDATE
        #            user_auth
        #        SET
        #            stripe_subscription_id = %s,
        #            stripe_subscription_status = 'paid'
        #        WHERE
        #            stripe_customer_id = %s
        #    """
        #    cursor.execute(query, (stripe_subscription_id, stripe_customer_id, ))
        #    conn.commit()

        #    if cursor.rowcount != 1:
        #        return '', 400
        #    return '', 200

        if event_type == 'invoice.paid':
            # payment success (first or next)
            stripe_customer_id = data['object']['customer']
            stripe_amount_paid = data['object']['amount_paid']
            stripe_subscription_id = data['object']['subscription']
            lines_data = data['object']['lines']['data']
            stripe_current_period_end = int(lines_data[0]['period']['end'])
            stripe_price = lines_data[0]['plan']['id']

            if stripe_price == app.config['STRIPE_PRICE_VIEWER']:
                subscription_status = SUBSCRIPTION_STATUS_VIEWER
                max_storage_gb = 0
            elif stripe_price == app.config['STRIPE_PRICE_100G']:
                if stripe_amount_paid > 0:
                    subscription_status = SUBSCRIPTION_STATUS_PAID
                    max_storage_gb = 100
                else:
                    subscription_status = SUBSCRIPTION_STATUS_TRIAL
                    max_storage_gb = 1
            else:
                return '', 400

            query = """
                UPDATE
                    user_auth
                SET
                    stripe_current_period_end = FROM_UNIXTIME(%s),
                    stripe_subscription_id = %s,
                    subscription_status = %s,
                    max_storage_gb = %s
                WHERE
                    stripe_customer_id = %s
            """
            cursor.execute(query, (
                stripe_current_period_end,
                stripe_subscription_id,
                subscription_status,
                max_storage_gb,
                stripe_customer_id, ))
            conn.commit()

            if cursor.rowcount != 1:
                return '', 400
            return '', 200

        elif event_type == 'invoice.payment_failed':
            stripe_customer_id = data['object']['customer']

            query = """
                UPDATE
                    user_auth
                SET
                    subscription_status = 'payment_failed'
                WHERE
                    stripe_customer_id = %s
            """
            cursor.execute(query, (stripe_customer_id, ))
            conn.commit()

            if cursor.rowcount != 1:
                return '', 400
            return '', 200
        else:
            # generic event - just commit user trx record
            conn.commit()

    return '', 200


## this is only for subscriptions NOT involving CC/payments
## see checkout_session_create and checkout_session_complete for Stripe-based subscriptions
#@apiv1_blueprint.route('/api/v1/subscribe', methods=['POST'])
#@lib.errors.exception_wrapper
#@flask_login.login_required
#def api_subscribe():
#    pack = lib.packer.unpack_value(request.data)
#    subscription_plan = pack['subscription_plan']
#
#    if subscription_plan not in [SUBSCRIPTION_PLAN_VIEWER, SUBSCRIPTION_PLAN_STANDARD_TRIAL]:
#        return '', 400
#
#    current_plan = flask_login.current_user.subscription_plan
#
#    if subscription_plan == SUBSCRIPTION_PLAN_STANDARD_TRIAL:
#        if current_plan in ["", SUBSCRIPTION_PLAN_VIEWER]:
#            with lib.database.connect() as conn:
#                cursor = lib.database.get_cursor(conn)
#                update_user_to_standard_trial_subscription(cursor)
#                conn.commit()
#                return '', 200
#        else:
#            return '', 409
#
#    elif subscription_plan == SUBSCRIPTION_PLAN_VIEWER:
#        # can switch to viewer:
#        # from standard and/or standard-trial if there are no files belonging to this user
#        # from no-plan
#        pass
#

@apiv1_blueprint.route('/api/v1/confirm-email', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_confirm_email():

    callid = log.new_callid()
    log.webapi(log.API_CALL_CONFIRMEMAIL, {"cid": callid})

    if flask_login.current_user.email_confirmed == "1":
        return '', 200

    pack = lib.packer.unpack_value(request.data)

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        if 'resend' in pack.keys():
            log.webapi(log.API_CALL_CONFIRMEMAIL, {"cid": callid, "resend": 1})

            query = """
                UPDATE user_auth
                SET email_confirmation_attempts = email_confirmation_attempts + 1
                WHERE id = %s AND email_confirmation_attempts < 2
            """
            cursor.execute(query, (flask_login.current_user.row_id, ))
            if cursor.rowcount == 1:
                lib.mail.send_email_confirmation_request(
                    flask_login.current_user.email,
                    flask_login.current_user.email_confirmed)
                conn.commit()
            return '', 200

        elif 'code' in pack.keys():
            code = pack['code']
            log.webapi(log.API_CALL_CONFIRMEMAIL, {"cid": callid, "code": code})
            query = """
                UPDATE user_auth
                SET email_confirmed = '1'
                WHERE id = %s AND email_confirmed = %s
            """
            cursor.execute(query, (flask_login.current_user.row_id, code))
            log.webapi(log.API_CALL_CONFIRMEMAIL, {"cid": callid, "rowcount": cursor.rowcount})
            if cursor.rowcount == 1:
                conn.commit()
                log.webapi(log.API_CALL_CONFIRMEMAIL_OK, {"cid": callid})
                return '', 200
            else:
                conn.rollback()
                log.webapi(log.API_CALL_CONFIRMEMAIL_ERROR, {"cid": callid})
                return '', 400


@apiv1_blueprint.route('/api/v1/user', methods=['PUT'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_user_update():

    pack = lib.packer.unpack_value(request.data)
    default_album_ident = pack['user']['default_album_ident']
    default_bucket_ident = pack['user']['default_bucket_ident']

    callid = log.new_callid()
    log.webapi(log.API_CALL_PUTUSER,
        {"cid": callid, "defalbum": default_album_ident, "defbucket": default_bucket_ident})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            UPDATE
                user_auth
            SET
                default_album=%s, default_bucket=%s
            WHERE
                id = %s"""

        cursor.execute(query,
            (default_album_ident, default_bucket_ident, flask_login.current_user.row_id))
        conn.commit()

        flask_login.current_user.default_album = default_album_ident
        flask_login.current_user.default_bucket = default_bucket_ident

        log.webapi(log.API_CALL_PUTUSER_OK, {"cid": callid})
        return '', 200

@apiv1_blueprint.route('/api/v1/password', methods=['PUT'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_change_password():

    callid = log.new_callid()
    log.webapi(log.API_CALL_PUTPASSWORD, {"cid": callid})

    pack = lib.packer.unpack_value(request.data)
    old_auth = pack['user']['old_auth']
    auth = pack['user']['auth']
    encrypted_private_key = pack['user']['encrypted_private_key']

    old_auth = base64.b64encode(old_auth)

    is_password_ok = bcrypt.checkpw(old_auth, flask_login.current_user.hashed)
    if not is_password_ok:
        log.webapi(log.API_CALL_PUTPASSWORD_ERROR, {"cid": callid, "error": 401})
        return '', 401

    auth_hash = bcrypt.hashpw(base64.b64encode(auth), bcrypt.gensalt())

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            UPDATE
                user_auth
            SET
                auth_hash=%s, private_key_nonce=%s
            WHERE
                id = %s"""

        cursor.execute(query,
            (auth_hash, encrypted_private_key, flask_login.current_user.row_id))
        conn.commit()

        log.webapi(log.API_CALL_PUTPASSWORD_OK, {"cid": callid})
        return '', 200


@apiv1_blueprint.route('/api/v1/user', methods=['DELETE'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_user_delete():

    callid = log.new_callid()
    log.webapi(log.API_CALL_DELETEUSER, {"cid": callid})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            UPDATE
                user_auth
            SET
                delete_timestamp = CURRENT_TIMESTAMP()
            WHERE
                id = %s
        """
        cursor.execute(query, (flask_login.current_user.row_id, ))
        conn.commit()

        flask_login.logout_user()
        log.webapi(log.API_CALL_DELETEUSER_OK, {"cid": callid})
        return '', 200


        # total_sz = select_user_total_system_bucket_size(cursor)

        # if total_sz > 0:
        #     log.webapi(log.API_CALL_DELETEUSER_ERROR, {"cid": callid, "error": 400})
        #     return '', 400

        # # this won't delete from shared_album albums shared with the user
        # # also won't delete from index_info
        # query = """
        #     DELETE
        #         u, b, a, af, sa, f /* delete from all tables */
        #     FROM
        #         user_auth u
        #     LEFT OUTER JOIN
        #         bucket b ON u.id = b.user_id
        #     LEFT OUTER JOIN
        #         album a ON u.id = a.user_id
        #     LEFT OUTER JOIN
        #         album_file af ON af.album_id = a.id
        #     LEFT OUTER JOIN
        #         file f ON f.id = af.file_id
        #     LEFT OUTER JOIN
        #         shared_album sa ON sa.album_id = a.id
        #     WHERE
        #         u.id = %s
        # """

        # cursor.execute(query, (flask_login.current_user.row_id, ))
        # conn.commit()

        # flask_login.logout_user()
        # log.webapi(log.API_CALL_DELETEUSER_OK, {"cid": callid})
        # return '', 200


@apiv1_blueprint.route('/api/v1/bucket', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_bucket_list():

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETBUCKET, {"cid": callid})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        query = """
            SELECT
                identifier,
                bucket_name,
                service,
                is_system,
                bucket_prefix
            FROM
                bucket
            WHERE
                user_id = %s
        """
        c.execute(query, (flask_login.current_user.row_id, ))
        rows = c.fetchall()

        bucket_list = []

        for row in rows:
            bucket_list.append({
                "identifier": row.identifier,
                "name": row.bucket_name,
                "service_id": row.service,
                "is_system": row.is_system,
                "bucket_prefix": row.bucket_prefix,
            })

        log.webapi(log.API_CALL_GETBUCKET_OK, {"cid": callid, "numbuckets": len(bucket_list)})
        return response_from_pack(lib.packer.pack_value({"buckets": bucket_list})), 200


@apiv1_blueprint.route('/api/v1/bucket', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_bucket_attach():

    bucket_identifier = 'bkt' + secrets.token_hex(16)

    pack = lib.packer.unpack_value(request.data)

    operation_type = pack['operation_type']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTBUCKET, {
      "cid": callid, "bucket": bucket_identifier, "optype": operation_type,
    })

    if operation_type == 'attach-existing':
        bucket_service = pack['bucket_service']
        bucket_name = pack['bucket_name']
        bucket_prefix = pack['bucket_prefix']
        bucket_id = pack['bucket_id']
        bucket_key_id = pack['bucket_key_id']
        bucket_key = pack['bucket_key']
        cors_autoconfig = pack['cors_autoconfig']

        client = lib.b2.Client()

        # check if bucket id/key are ok
        auth_ok = client.authorize_account(bucket_key_id, bucket_key)
        if not auth_ok:
            log.webapi(log.API_CALL_POSTBUCKET_ERROR,
                {"cid": callid, "error": 400, "point": 'A'})
            return 'bucket authorization failed', 400

        is_test = app.config['MEDIASERVICE_ENV'] == "test"

        # auto-config CORS if requested
        if cors_autoconfig == 1:
            cors_autoconfig_resp_status = client.update_bucket(bucket_id, lib.b2.get_cors_rules(is_test))
            print("cors_autoconfig_resp_status", cors_autoconfig_resp_status)

            if cors_autoconfig_resp_status == 200:
                pass
            else:
                log.webapi(log.API_CALL_POSTBUCKET_ERROR, {"cid": callid, "error": 400, "point": 'AA'})
                return 'CORS auto-config failed', 400


        # check if bucket cors settings are ok
        bucket_list = client.list_buckets(bucket_id)
        if not bucket_list:
            log.webapi(log.API_CALL_POSTBUCKET_ERROR,
                {"cid": callid, "error": 400, "point": 'B'})
            return 'invalid bucket id', 400

        cors_rules = bucket_list[0]['corsRules']

        if not cors_rules:
            log.webapi(log.API_CALL_POSTBUCKET_ERROR,
                {"cid": callid, "error": 400, "point": 'C'})
            return 'invalid cors settings: no CORS rules found', 400

        cr = cors_rules[0]
        cors_validation_result, cors_validation_message = lib.b2.validate_cors_rule(cr, is_test)
        if not cors_validation_result:
            return 'invalid cors settings: %s' % (cors_validation_message, ), 400

        encrypted_bucket_key = adminapi.encrypt_bucket_key(bucket_key)

        if encrypted_bucket_key is None:
          log.webapi(log.API_CALL_POSTBUCKET_ERROR,
            {"cid": callid, "point": "encrypt_bucket_key failed", "status": r.status_code})
          return '', r.status_code

        with lib.database.connect() as conn:
            cursor = lib.database.get_cursor(conn)
            query = """
                INSERT INTO bucket (
                  identifier, user_id, is_system, service, bucket, bucket_name, bucket_prefix,
                  bucket_key_id, bucket_key, encrypted_bucket_key)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '', %s)
            """
            cursor.execute(query, (bucket_identifier, flask_login.current_user.row_id,
                0, bucket_service, bucket_id, bucket_name, bucket_prefix, bucket_key_id,
                encrypted_bucket_key))

            conn.commit()

        log.webapi(log.API_CALL_POSTBUCKET_OK, {"cid": callid})
        return '', 200

    elif operation_type == 'attach-new':
        master_key_id = pack['master_key_id']
        master_key = pack['master_key']

        r = adminapi.attach_new_bucket(flask_login.current_user.row_id, master_key_id, master_key)

        if r.status_code != 200:
          log.webapi(log.API_CALL_POSTBUCKET_ERROR,
            {"cid": callid, "point": "adminapi.attach_new_bucket", "status": r.status_code})
          return '', r.status_code

        log.webapi(log.API_CALL_POSTBUCKET_OK, {"cid": callid})
        return response_from_pack(r.content), r.status_code
    else:
        log.webapi(log.API_CALL_POSTBUCKET_ERROR, {"cid": callid, "point": "BADOPTYPE"})
        return '', 400

@apiv1_blueprint.route('/api/v1/bucket', methods=['DELETE'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_bucket_delete():

    bucket_identifier = request.args.get("bucket")

    callid = log.new_callid()
    log.webapi(log.API_CALL_DELETEBUCKET, {"cid": callid, "bucket": bucket_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        albums = select_album_identifiers_by_bucket_identifier(cursor, bucket_identifier)
        if len(albums) > 0:
            log.webapi(log.API_CALL_DELETEBUCKET_ERROR, {"cid": callid, "error": 400})
            return '', 400

        delete_bucket(cursor, bucket_identifier)
        conn.commit()

        log.webapi(log.API_CALL_DELETEBUCKET_OK, {"cid": callid})
        return '', 200


@apiv1_blueprint.route('/api/v1/album-day-list', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_album_active_day_list():

    callid = log.new_callid()
    log.webapi(log.API_CALL_ALBUMACTIVEDAYLIST, {"cid": callid})

    album_identifier = request.args.get("album")
    year = request.args.get("year")

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        rows = select_album_active_day_list(c, album_identifier, year)

        day_list = [int(row[0]) for row in rows]

        log.webapi(log.API_CALL_ALBUMACTIVEDAYLIST_OK, {"cid": callid})
        return response_from_pack(lib.packer.pack_value([{
            "year": year,
            "days": day_list,
        }])), 200


@apiv1_blueprint.route('/api/v1/album', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
def api_album_list():

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETALBUM, {"cid": callid})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)
        rows = select_albums(c)

        album_list = []

        for row in rows:
            album_share_count = len(select_album_share_list(c, row.identifier)) \
                if row.own_album else 0

            share_list_rows = select_album_share_list(c, row.identifier)
            share_list = [{"email_to": r.email, "can_add_files": r.can_add_files}
                for r in share_list_rows]

            album_list.append({
                "identifier": row.identifier,
                "encrypted_album_key": row.album_key_nonce,
                "encrypted_data": row.data_nonce,
                "created": row.created,
                "bucket_name": row.bucket_name,
                "bucket_identifier": row.bucket_identifier,
                "bucket_prefix": row.album_bucket_prefix,
                "bucket_size": 0 if row.bucket_size is None else int(row.bucket_size),
                "file_count": row.count if row.count is not None else 0,
                "min_date": 0 if row.min_date is None else row.min_date,
                "max_date": 0 if row.max_date is None else row.max_date,
                "public_key": row.public_key,
                "shared_album_owner_email": row.shared_album_owner_email,
                "shared_album_can_add_files": row.shared_album_can_add_files,
                "share_list": share_list,
                "accepted": row.accepted,
                "encrypted": row.encrypted,
            })

        log.webapi(log.API_CALL_GETALBUM_OK, {"cid": callid})
        return response_from_pack(lib.packer.pack_value({"albums": album_list})), 200

@apiv1_blueprint.route('/api/v1/album', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_album_create():

    album_identifier = 'alb' + secrets.token_hex(16)
    album_bucket_prefix = 'pfx' + secrets.token_hex(16)

    pack = lib.packer.unpack_value(request.data)
    data = pack['album']

    encrypted = data['encrypted']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTALBUM,
        {"cid": callid, "album": album_identifier, "prefix": album_bucket_prefix,
            "enc": encrypted})

    if encrypted:
        encrypted_album_key = data['encrypted_album_key']
        album_data = data['encrypted_album_data']
        bucket_identifier = data['bucket_identifier']
    else:
        encrypted_album_key = bytes()
        album_data = data['clear_album_data']
        bucket_identifier = data['bucket_identifier']

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        bucket_rows = select_bucket_by_identifier(cursor, bucket_identifier)

        if len(bucket_rows) != 1:
            log.webapi(log.API_CALL_POSTALBUM_ERROR, {"cid": callid, "error": 401})
            return '', 401

        bucket_id = bucket_rows[0].id
        bucket_prefix = bucket_rows[0].bucket_prefix
        bucket_bucketid = bucket_rows[0].bucket
        bucket_key_id = bucket_rows[0].bucket_key_id
        bucket_key = adminapi.decrypt_bucket_key(bucket_id)

        if bucket_key is None:
            log.webapi(
              log.API_CALL_POSTALBUM_ERROR,
              {"cid": callid, "point": "decrypt_bucket_key: failed", "error": 401},
            )
            return '', 401

        client = lib.b2.Client()

        if bucket_rows[0].is_system == 1:
            client.authorize_account(
                app.config['MEDIASERVICE_B2_KEYID'],
                app.config['MEDIASERVICE_B2_KEY'])

            album_bucket_key_id, album_bucket_key = \
                client.create_key_for_prefix(bucket_bucketid, album_bucket_prefix)
        else:
            client.authorize_account(bucket_key_id, bucket_key)
            album_bucket_key_id, album_bucket_key = bucket_key_id, bucket_key

        encrypted_album_bucket_key = adminapi.encrypt_bucket_key(album_bucket_key)
        if encrypted_album_bucket_key is None:
            log.webapi(
              log.API_CALL_POSTALBUM_ERROR,
              {"cid": callid, "point": "encrypt_bucket_key: failed", "error": 401},
            )
            return '', 401

        insert_album(
            cursor,
            flask_login.current_user.row_id,
            bucket_id,
            album_identifier,
            encrypted_album_key,
            album_data,
            bucket_prefix + album_bucket_prefix,
            album_bucket_key_id,
            encrypted,
            encrypted_album_bucket_key)

        conn.commit()

        log.webapi(log.API_CALL_POSTALBUM_OK, {"cid": callid})
        return response_from_pack(
            lib.packer.pack_value({"album_identifier": album_identifier})), 200

@apiv1_blueprint.route('/api/v1/album', methods=['PUT'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_album_update():

    pack = lib.packer.unpack_value(request.data)
    data = pack['album']

    album_data = data['album_data']
    album_identifier = data['identifier']

    callid = log.new_callid()
    log.webapi(log.API_CALL_PUTALBUM,
        {"cid": callid, "album": album_identifier, "datalen": len(album_data)})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        rowcount = update_album(cursor, album_identifier, album_data)

        if rowcount == 1:
            conn.commit()
            log.webapi(log.API_CALL_PUTALBUM_OK, {"cid": callid})
            return '', 200
        else:
            conn.rollback()
            log.webapi(log.API_CALL_PUTALBUM_ERROR, {"cid": callid, "error": 400})
            return '', 400


@apiv1_blueprint.route('/api/v1/album', methods=['DELETE'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_album_delete():

    album_identifier = request.args.get("album")

    callid = log.new_callid()
    log.webapi(log.API_CALL_DELETEALBUM, {"cid": callid, "album": album_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)
        deleted_rows = delete_album(cursor, album_identifier)

        if deleted_rows == 1:
            conn.commit()
            log.webapi(log.API_CALL_DELETEALBUM_OK, {"cid": callid})
            return '', 200
        else:
            conn.rollback()
            log.webapi(log.API_CALL_DELETEALBUM_ERROR, {"cid": callid, "error": 400})
            return '', 400


@apiv1_blueprint.route('/api/v1/bucket-upload-token', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_bucket_upload_token():

    pack = lib.packer.unpack_value(request.data)
    album_identifier = pack['album']['identifier']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN, {"cid": callid, "album": album_identifier})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        album_rows = select_album(c, album_identifier)
        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        row = album_rows[0]

        if row.can_add_files != 1:
            log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        bucket_id = row.bucket
        is_system = row.is_system
        album_bucket_key_id = row.bucket_prefix_key_id
        album_bucket_key = adminapi.decrypt_album_prefix_bucket_key(row.id)

        if album_bucket_key is None:
            log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": "decrypt_album_prefix_bucket_key failed"})
            return '', 400

        if is_system: # album in system system bucket
            test_env = app.config['MEDIASERVICE_ENV'] == "test"

            if test_env:
                max_system_storage_bytes = flask_login.current_user.max_storage_gb*1000*1000*100    # 100 MB in test
            else:
                max_system_storage_bytes = flask_login.current_user.max_storage_gb*1000*1000*1000   # 1000 MB in prod

            used_system_space_bytes = select_user_total_system_bucket_used_space_bytes(c)

            # currently quota enforcement is done at 2 points:
            # - backend: bucket-upload-token wont return a new token if system bucket quota is exhausted
            # - frontend: will check available space before file upload
            # justification: this way, we never fail an upload because of quota, which simplifies storage
            # management (no need to track for files uploaded to bucket, but failed to register via POST /file)

            if used_system_space_bytes > max_system_storage_bytes:
                log.webapi(log.API_CALL_POSTFILE_ERROR, {"cid": callid, "error": 413, "point": "quota"})
                return '', 413

        client = lib.b2.Client()
        auth_ok = client.authorize_account(album_bucket_key_id, album_bucket_key)
        if not auth_ok:
            log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        upload_url, upload_auth = client.get_upload_url(bucket_id)

        pack = lib.packer.pack_value({
            'bucket': {
                'upload_url': upload_url,
                'upload_auth': upload_auth,
            },
        })

        log.webapi(log.API_CALL_POSTBUCKETUPLOADTOKEN_OK,
            {"cid": callid, "urllen": len(upload_url)})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/album-download-token', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_bucket_download_token():

    pack = lib.packer.unpack_value(request.data)
    album_identifier = pack['album']['identifier']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTALBUMDOWNLOADTOKEN, {"cid": callid, "album": album_identifier})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        cache_rows = select_download_auth_cache_for_album(c, album_identifier)
        if len(cache_rows) > 0:
            pack = lib.packer.pack_value({
                'album': {
                    'download_url': cache_rows[0].url,
                    'download_auth': cache_rows[0].auth,
                    'expires': cache_rows[0].expires,
                },
            })
            log.webapi(log.API_CALL_POSTALBUMDOWNLOADTOKEN_OK,
                {"cid": callid, "cachehit": 1})
            return response_from_pack(pack), 200

        album_rows = select_album(c, album_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTALBUMDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400})
            return '', 400

        row = album_rows[0]
        bucket_key_prefix = row.album_bucket_prefix
        bucket_id = row.bucket
        api_key_id = row.bucket_prefix_key_id
        api_key = adminapi.decrypt_album_prefix_bucket_key(row.id)

        client = lib.b2.Client()
        if not client.authorize_account(api_key_id, api_key):
            log.webapi(log.API_CALL_POSTALBUMDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 401})
            return '', 401

        auth_duration = 86400
        download_auth, expires = client.get_download_auth(
            bucket_id, bucket_key_prefix, auth_duration)

        insert_download_auth_cache_for_album(
            c, row.bucket_id, row.id, client.api_url, download_auth, expires)
        conn.commit()

        pack = lib.packer.pack_value({
            'album': {
                'download_url': client.api_url,
                'download_auth': download_auth,
                'expires': expires,
            },
        })

        log.webapi(log.API_CALL_POSTALBUMDOWNLOADTOKEN_OK, {"cid": callid})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/file', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_file_create():

    pack = lib.packer.unpack_value(request.data)
    data = pack['file']
    album_identifier = data['album']
    encrypted = data['encrypted']
    bucket_size = data['bucket_size']
    media_type = data['media_type']

    if encrypted:
        encrypted_file_key = data['encrypted_key']
        file_data = data['encrypted_data']
        file_comment = \
            data['encrypted_comment'] if 'encrypted_comment' in data else ''
    else:
        encrypted_file_key = bytes()
        file_data = data['clear_data']
        file_comment = \
            data['clear_comment'] if 'clear_comment' in data else ''

    after_identifier = \
        data['after_identifier'] if 'after_identifier' in data else None
    file_date = data['file_date'] if 'file_date' in data else None
    bucket_file_id = data['bucket_file_id']
    bucket_file_name = data['bucket_file_name']
    bucket_thumb_id = data['bucket_thumb_id']
    bucket_thumb_name = data['bucket_thumb_name']
    ordering = data['ordering'] if 'ordering' in data else 0

    file_identifier = 'fle' + secrets.token_hex(16)

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTFILE,
        {"cid": callid, "file": file_identifier, "album": album_identifier, "enc": encrypted})

    user_id = flask_login.current_user.row_id

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        album_rows = select_album(c, album_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTFILE_ERROR, {"cid": callid, "error": 400, "point": 1})
            return '', 400

        if album_rows[0].can_add_files != 1:
            log.webapi(log.API_CALL_POSTFILE_ERROR, {"cid": callid, "error": 400, "point": 2})
            return '', 400

        album_id = album_rows[0].id
        album_owner_id = album_rows[0].user_id

        if file_date is not None:
            query = """
                INSERT INTO file (identifier, user_id, creator_id, data_nonce,
                    file_date, ordering, bucket_size, comment, media_type,
                    bucket_file_id, bucket_file_name, bucket_thumb_id, bucket_thumb_name,
                    encrypted)
                VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
            c.execute(query, (file_identifier,
                album_owner_id, user_id, file_data, file_date, ordering, bucket_size,
                file_comment, media_type, bucket_file_id, bucket_file_name,
                bucket_thumb_id, bucket_thumb_name, encrypted))
        else:
            query = """
                INSERT INTO file (identifier, user_id, creator_id, data_nonce,
                    file_date, ordering, bucket_size, comment, media_type,
                    bucket_file_id, bucket_file_name, bucket_thumb_id, bucket_thumb_name)
                VALUES
                    (%s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            c.execute(query, (file_identifier,
                album_owner_id, user_id, file_data, ordering, bucket_size, file_comment,
                media_type, bucket_file_id, bucket_file_name,
                bucket_thumb_id, bucket_thumb_name, encrypted))

        file_id = c.lastrowid

        if ordering == 0:
            ordering = file_id

            # use after_identifier to set the ordering, otherwise
            # assign ordering from the id
            if after_identifier is not None:
                ordering_value = 0
                if after_identifier != "":
                    query = """
                        SELECT
                            ordering
                        FROM
                            file f,
                            album_file af
                        WHERE
                            f.user_id = %s
                            AND f.identifier = %s
                            AND f.id = af.file_id
                            AND af.album_id = %s
                            AND f.deleted IS NULL
                        """
                    c.execute(query, (album_owner_id, after_identifier, album_id))

                    rows = c.fetchall()
                    if len(rows) == 1:
                        ordering_value = rows[0].ordering

                query = """
                    UPDATE
                        file f,
                        album_file af
                    SET
                        f.ordering = f.ordering + 1
                    WHERE
                        f.user_id = %s
                        AND file_date = (SELECT file_date FROM file WHERE id = %s)
                        AND af.file_id = f.id
                        AND af.album_id = %s
                        AND f.ordering > %s
                        AND f.deleted IS NULL
                """
                c.execute(query, (album_owner_id, file_id, album_rows[0].id, ordering_value))

                ordering = ordering_value + 1

        query = """
            UPDATE file SET ordering = %s WHERE id = %s AND deleted IS NULL
        """
        c.execute(query, (ordering, file_id, ))

        query = """
            INSERT INTO album_file (
                album_id,
                file_id,
                file_key_nonce
            )
            VALUES
                (%s, %s, %s)
        """
        c.execute(query, (album_rows[0].id, file_id, encrypted_file_key))

        conn.commit()

        pack = lib.packer.pack_value({
            'file': {
                'identifier': file_identifier,
            },
        })

        log.webapi(log.API_CALL_POSTFILE_OK, {"cid": callid})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/file-position', methods=['PUT'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_file_update_position():

    pack = lib.packer.unpack_value(request.data)
    # source is the moved file
    source_identifier_list = pack['source_file_list']
    target_identifier = pack['target_file']
    pos_before = pack['position_before']

    callid = log.new_callid()
    log.webapi(log.API_CALL_PUTFILEPOSITION, {"cid": callid,
        "src": source_identifier_list, "tgt": target_identifier, "bfr": pos_before})

    source_identifier_list_len = len(source_identifier_list)

    if source_identifier_list_len < 1 or source_identifier_list_len > 1000:
            log.webapi(log.API_CALL_PUTFILEPOSITION,
                {"cid": callid, "error": 400, "point": 0, "len": source_identifier_list_len})
            return '', 400

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        album_identifier_rows = select_album_identifier_by_file_identifier(
            c, file_identifier=source_identifier_list[0])

        if len(album_identifier_rows) != 1:
            log.webapi(log.API_CALL_PUTFILEPOSITION,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        album_identifier = album_identifier_rows[0].identifier
        album_rows = select_album(c, album_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_PUTFILEPOSITION,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        if album_rows[0].can_add_files != 1:
            log.webapi(log.API_CALL_PUTFILEPOSITION,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        # NOTE1: since we have checked that album is writable above
        # it should be ok to test (source.user_id = %s OR source.creator_id = %s)
        # Without the above album check, testing for user/creator would be not sufficient

        # NOTE2: source_identifier_list first entry is assumed to be the highest in the timeline

        ba_offset = (0 if pos_before else 1)
        source_ordering_value_list = [item for sublist in zip(
            source_identifier_list,
            list(range(ba_offset, source_identifier_list_len + ba_offset))
        ) for item in sublist]

        update_items_query_params = \
            source_ordering_value_list + \
            [flask_login.current_user.row_id, flask_login.current_user.row_id,] + \
            source_identifier_list + \
            [target_identifier]

        source_identifier_list_placeholders = ','.join(['%s']*source_identifier_list_len)
        source_position_list_placeholders = ' '.join(["\n WHEN %s THEN (target.ordering + %s) \n"]*source_identifier_list_len)

        query = """
            UPDATE
                file source,
                file target
            SET
                source.file_date = target.file_date,
                source.ordering = (CASE source.identifier """ + source_position_list_placeholders + """ END)
            WHERE
                (source.user_id = %s OR source.creator_id = %s)
                AND target.user_id = source.user_id
                AND source.identifier IN (""" + source_identifier_list_placeholders + """)
                AND target.identifier = %s
                AND source.deleted IS NULL
                AND target.deleted IS NULL
        """

        c.execute(query, tuple(update_items_query_params))

        # join (f, fs) is to update only files from the same album/date as the moved files, so any moved
        # file is suitable for that, we use source_identifier_list[0]
        # (note that the date of the moved files was already set by the above query)

        query = """
            UPDATE
                file f,
                file sf,
                album_file af,
                album_file source_af
            SET
                f.ordering = f.ordering + %s
            WHERE
                (sf.user_id = %s OR sf.creator_id = %s)
                AND sf.identifier = %s
                AND source_af.file_id = sf.id
                AND source_af.album_id = af.album_id
                AND af.file_id = f.id
                AND f.user_id = sf.user_id
                AND f.file_date = sf.file_date
                AND f.ordering >= sf.ordering
                AND f.identifier NOT IN (""" + source_identifier_list_placeholders + """)
                AND f.deleted IS NULL
                AND sf.deleted IS NULL
        """

        update_ordering_query_params = [
            source_identifier_list_len + ba_offset,
            flask_login.current_user.row_id,
            flask_login.current_user.row_id,
            source_identifier_list[0],
        ] + source_identifier_list

        c.execute(query, tuple(update_ordering_query_params))
        conn.commit()

    log.webapi(log.API_CALL_PUTFILEPOSITION_OK, {"cid": callid})
    return '', 200


@apiv1_blueprint.route('/api/v1/file', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_file_list():

    album_identifier = request.args.get("album")

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETFILE, {"cid": callid, "album": album_identifier})

    if not album_identifier_re.fullmatch(album_identifier):
        log.webapi(log.API_CALL_GETFILE_ERROR, {"cid": callid, "error": 400, "point": 1})
        return '', 400

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        album_rows = select_album(c, album_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_GETFILE_ERROR, {"cid": callid, "error": 400, "point": 2})
            return '', 400

        encrypted = album_rows[0].encrypted

        start_file_id = request.args.get("fid")
        log.webapi(log.API_CALL_GETFILE, {"cid": callid, "fid": start_file_id})

        end_file_id = request.args.get("efid")
        log.webapi(log.API_CALL_GETFILE, {"cid": callid, "efid": start_file_id})

        if start_file_id is not None:
            file_rows = select_album_files_older_than_file_id(
                c, album_rows[0].id, start_file_id)
        elif end_file_id is not None:
            file_rows = select_album_files_newer_than_file_id(
                c, album_rows[0].id, end_file_id)

            # reverse the list. because we are selecting "up" from
            # a given record, the record comes first in the select ordering.
            # however in the resulting list, this record will be the oldest
            # and therefore needs to be the last
            file_rows = file_rows[::-1]
        else:
            position = request.args.get("yyyymmdd")

            ## validate position
            #if position is not None:
            #    position = int(position)
            #    album_max_pos = album_rows[0].max_date // 100
            #    album_min_pos = album_rows[0].min_date // 100
            #    if not (album_min_pos <= position <= album_max_pos) or \
            #            not(1 <= (position % 100) <= 12):
            #        position = None

            if position is None:
                if album_rows[0].max_date is not None:
                    position = album_rows[0].max_date
                else:
                    position = 0

            log.webapi(log.API_CALL_GETFILE, {"cid": callid, "pos": position})

            file_rows = select_album_files_at_or_before_date(c, album_rows[0].id, position)

        files = []

        for row in file_rows:
            files.append({
                'identifier': row.identifier,
                'encrypted_key': row.file_key_nonce,
                'encrypted_data': row.data_nonce if encrypted else 0,
                'clear_data': row.data_nonce if not encrypted else 0,
                'file_date': row.file_date,
                'file_ordering': row.file_ordering,
                'comment': row.comment,
                'bucket_size': row.bucket_size,
                'can_edit_file': row.can_edit_file,
                'can_delete_file': row.can_delete_file,
            })

        log.webapi(log.API_CALL_GETFILE_OK, {"cid": callid})
        return response_from_pack(lib.packer.pack_value({'files': files})), 200


@apiv1_blueprint.route('/api/v1/file-comment', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_file_comment_set():

    pack = lib.packer.unpack_value(request.data)

    file_identifier = pack['file']
    comment_nonce = pack['comment']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTFILECOMMENT, {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        if is_own_file(c, file_identifier=file_identifier):
            query = """
                UPDATE
                    file
                SET
                    comment = %s
                WHERE
                    user_id = %s
                    AND identifier = %s
                    AND deleted IS NULL
                """
        else:
            query = """
                UPDATE
                    file
                SET
                    comment = %s
                WHERE
                    creator_id = %s
                    AND identifier = %s
                """

        c.execute(query, (
            comment_nonce,
            flask_login.current_user.row_id,
            file_identifier))

        conn.commit()
        log.webapi(log.API_CALL_POSTFILECOMMENT_OK, {"cid": callid})
        return '', 200

@apiv1_blueprint.route('/api/v1/file', methods=['DELETE'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_file_delete():

    file_identifier = request.args.get("file")
    # b2_file_id = request.args.get("fid")
    # b2_file_name = request.args.get("fn")
    # b2_thumb_id = request.args.get("tid")
    # b2_thumb_name = request.args.get("tn")
    # b2_large_file_id = request.args.get("lid")
    # b2_large_file_name = request.args.get("ln")

    callid = log.new_callid()
    log.webapi(log.API_CALL_DELETEFILE, {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            UPDATE
                file
            SET
                deleted = CURRENT_TIMESTAMP
            WHERE
                user_id = %s
                AND identifier = %s
                AND deleted IS NULL
        """

        cursor.execute(query, (flask_login.current_user.row_id, file_identifier, ))
        conn.commit()

        log.webapi(log.API_CALL_DELETEFILE_OK, {"cid": callid})
        return '', 200

        # if b2_file_id is not None and \
        #         len(b2_file_id) > 0 and \
        #         b2_thumb_id is not None and \
        #         len(b2_thumb_id) > 0:
        #     album_rows = select_own_album_identifier_by_file_identifier(
        #         cursor, file_identifier)

        #     if len(album_rows) != 1:
        #         log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #             {"cid": callid, "error": 400, "point": 1})
        #         return '', 400

        #     album_identifier = album_rows[0].identifier

        #     album_rows = select_album(cursor, album_identifier)
        #     if len(album_rows) != 1:
        #         log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #             {"cid": callid, "error": 400, "point": 2})
        #         return '', 400

        #     row = album_rows[0]
        #     bucket_id = row.bucket
        #     album_bucket_key_id = row.bucket_prefix_key_id
        #     album_bucket_key = row.bucket_prefix_key

        #     client = lib.b2.Client()
        #     client.authorize_account(album_bucket_key_id, album_bucket_key)
        #     status = client.delete_file(b2_file_name, b2_file_id)
        #     if status != 200:
        #        log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #            {"cid": callid, "error": 400, "point": 3})
        #        return '', 400
        #     status = client.delete_file(b2_thumb_name, b2_thumb_id)
        #     if status != 200:
        #        log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #            {"cid": callid, "error": 400, "point": 4})
        #        return '', 400
        #     if b2_large_file_id != None and b2_large_file_name != None:
        #        status = client.delete_file(b2_large_file_name, b2_large_file_id)
        #        if status != 200:
        #            log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #                {"cid": callid, "error": 400, "point": 5})
        #            return '', 400

        #        delete_index_info(cursor, file_identifier)

        # deleted_rows = delete_file(cursor, file_identifier)

        # if deleted_rows == 2: # file, album_file
        #     conn.commit()
        #     log.webapi(log.API_CALL_DELETEFILE_OK, {"cid": callid})
        #     return '', 200
        # else:
        #     conn.rollback()
        #     log.webapi(log.API_CALL_DELETEFILE_ERROR,
        #         {"cid": callid, "error": 400, "point": 6})
        #     return '', 400

@apiv1_blueprint.route('/api/v1/file-delete', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_file_bulkdelete():

    pack = lib.packer.unpack_value(request.data)
    delete_file_list = pack['delete_file_list']

    callid = log.new_callid()
    log.webapi(log.API_CALL_BULKDELETEFILE, {"cid": callid, "file_list": delete_file_list})

    placeholders = ", ".join(["%s"]*len(delete_file_list))

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = f"""
            UPDATE
                file
            SET
                deleted = CURRENT_TIMESTAMP
            WHERE
                user_id = %s
                AND identifier IN ({placeholders})
                AND deleted IS NULL
        """

        params = [flask_login.current_user.row_id] + [f['identifier'] for f in delete_file_list]

        cursor.execute(query, params)
        conn.commit()

        log.webapi(log.API_CALL_BULKDELETEFILE_OK, {"cid": callid})
        return '', 200


@apiv1_blueprint.route('/api/v1/file-download-token', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_file_download_token():

    """
    currently used with direct links only
    """

    pack = lib.packer.unpack_value(request.data)
    file_identifier = pack['file_identifier']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN, {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        query = """
            SELECT
                f.identifier file_identifier,
                f.bucket_file_name bucket_file_name,
                f.bucket_thumb_name bucket_thumb_name,
                ii.bucket_file_name bucket_large_file_name,
                a.id album_id,
                a.album_bucket_prefix album_bucket_prefix,
                a.bucket_prefix_key_id bucket_prefix_key_id,
                b.bucket bucket_id
            FROM
                file f
            JOIN
                album_file af ON f.id = af.file_id
            JOIN
                album a ON a.id = af.album_id
            JOIN
                bucket b ON a.bucket_id = b.id
            LEFT OUTER JOIN
                index_info ii ON ii.file_id = f.id
            WHERE
                f.identifier = %s
                AND f.user_id = %s
                AND f.deleted IS NULL
        """

        c.execute(query, (file_identifier, flask_login.current_user.row_id))
        rows = c.fetchall()
        if len(rows) != 1:
            log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        bucket_key_prefix = rows[0].album_bucket_prefix
        bucket_id = rows[0].bucket_id
        api_key_id = rows[0].bucket_prefix_key_id
        api_key = adminapi.decrypt_album_prefix_bucket_key(rows[0].album_id)
        bucket_file_name = rows[0].bucket_file_name
        bucket_thumb_name = rows[0].bucket_thumb_name
        bucket_large_file_name = rows[0].bucket_large_file_name

        if api_key is None:
            log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": "decrypt_album_prefix_bucket_key failed"}
            )
            return '', 400

        client = lib.b2.Client()
        if not client.authorize_account(api_key_id, api_key):
            log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        auth_duration = 86400

        file_download_auth, file_expires = \
            client.get_download_auth(bucket_id, bucket_file_name, auth_duration, is_file=True)

        if not file_download_auth:
            log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        thumb_download_auth, thumb_expires = \
            client.get_download_auth(bucket_id, bucket_thumb_name, auth_duration, is_file=True)

        if not thumb_download_auth:
            log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                {"cid": callid, "error": 400, "point": 4})
            return '', 400

        large_file_download_auth, large_file_expires = "", ""

        if bucket_large_file_name:
            large_file_download_auth, large_file_expires = client.get_download_auth(
                bucket_id, bucket_large_file_name, auth_duration, is_file=True)

            if not thumb_download_auth:
                log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_ERROR,
                    {"cid": callid, "error": 400, "point": 5})
                return '', 400
        else:
            bucket_large_file_name = ""

        pack = lib.packer.pack_value({
            'download_url': client.api_url,
            'file_name': bucket_file_name,
            'file_download_auth': file_download_auth,
            'file_expires': file_expires,
            'thumb_name': bucket_thumb_name,
            'thumb_download_auth': thumb_download_auth,
            'thumb_expires': thumb_expires,
            'large_file_download_auth': large_file_download_auth,
            'large_file_expires': large_file_expires,
            'large_file_name': bucket_large_file_name,
        })

        log.webapi(log.API_CALL_POSTFILEDOWNLOADTOKEN_OK,
            {"cid": callid, "expires": file_expires})

        return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/file-direct-link', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@paid_subscription_required
def api_file_insert_direct_link():

    pack = lib.packer.unpack_value(request.data)
    file_identifier = pack['file_identifier']
    encrypted_data = pack['data']
    link_key = pack['link_key']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTFILEDIRECTLINK,
        {"cid": callid, "file": file_identifier, "linkkey": link_key})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            INSERT INTO direct_link
                (link_key, file_id, expires, data_nonce)
            SELECT
                %s, id, CURRENT_TIMESTAMP + INTERVAL 1 DAY, %s
            FROM
                file
            WHERE
                identifier = %s
                AND user_id = %s
                AND deleted IS NULL
        """
        cursor.execute(query,
            (link_key, encrypted_data, file_identifier, flask_login.current_user.row_id))
        conn.commit()

        log.webapi(log.API_CALL_POSTFILEDIRECTLINK_OK, {"cid": callid})
        return '', 200


@apiv1_blueprint.route('/api/v1/file-direct-link', methods=['GET'])
@lib.errors.exception_wrapper
def api_file_get_direct_link():

    """
    NOTE: this method is called by anonymous users
    """

    link_key = request.args.get("key")

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETFILEDIRECTLINK, {"cid": callid, "linkkey": link_key})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        query = """
            SELECT
                data_nonce
            FROM
                direct_link
            WHERE
                link_key = %s
                AND expires > CURRENT_TIMESTAMP
        """
        cursor.execute(query, (link_key, ))
        rows = cursor.fetchall()

        if len(rows) != 1:
            log.webapi(log.API_CALL_GETFILEDIRECTLINK_ERROR, {"cid": callid, "error": 400})

        pack = lib.packer.pack_value({
            'data': rows[0].data_nonce,
        })

        log.webapi(log.API_CALL_POSTFILEDIRECTLINK_OK, {"cid": callid})
        return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/large-file-start', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_large_file_start():

    pack = lib.packer.unpack_value(request.data)
    file_identifier = pack['file_identifier']
    encrypted = pack['encrypted']
    clear_filename = pack['clear_filename']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTLARGEFILESTART,
        {"cid": callid, "file": file_identifier, "enc": encrypted})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        album_rows = select_album_identifier_by_file_identifier(
            cursor, file_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILESTART_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        album_identifier = album_rows[0].identifier

        album_rows = select_album(cursor, album_identifier)
        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILESTART_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        row = album_rows[0]

        if row.can_add_files != 1:
            log.webapi(log.API_CALL_POSTLARGEFILESTART_ERROR,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        bucket_id = row.bucket
        album_bucket_key_id = row.bucket_prefix_key_id
        album_bucket_key = adminapi.decrypt_album_prefix_bucket_key(row.id)
        album_bucket_prefix = row.album_bucket_prefix

        if album_bucket_key is None:
            log.webapi(
              log.API_CALL_POSTLARGEFILESTART_ERROR,
              {"cid": callid, "error": 400, "point": "decrypt_album_prefix_bucket_key"},
            )
            return '', 400

        client = lib.b2.Client()
        client.authorize_account(album_bucket_key_id, album_bucket_key)

        if encrypted:
            file_name = album_bucket_prefix + "/" + file_identifier
        else:
            file_name = album_bucket_prefix + "/" + clear_filename

        file_id = client.start_large_file(bucket_id, file_name)

        pack = lib.packer.pack_value({
            'file_id': file_id,
            'file_bucket_path': file_name,
        })

        log.webapi(log.API_CALL_POSTLARGEFILESTART_OK, {"cid": callid})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/large-file-part-upload-url', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_large_file_get_part_upload_url():

    file_identifier = request.args.get("file")
    b2_file_id = request.args.get("fid")

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL,
        {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        album_rows = select_album_identifier_by_file_identifier(
            cursor, file_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        album_identifier = album_rows[0].identifier

        album_rows = select_album(cursor, album_identifier)
        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        row = album_rows[0]

        if row.can_add_files != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL_ERROR,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        bucket_id = row.bucket
        album_bucket_key_id = row.bucket_prefix_key_id
        album_bucket_key = adminapi.decrypt_album_prefix_bucket_key(row.id)
        album_bucket_prefix = row.album_bucket_prefix

        if album_bucket_key is None:
            log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL_ERROR,
                {"cid": callid, "error": 400, "point": "decrypt_album_prefix_bucket_key failed"})
            return '', 400

        client = lib.b2.Client()
        client.authorize_account(album_bucket_key_id, album_bucket_key)
        upload_url, upload_token = client.get_upload_part_url(b2_file_id)

        pack = lib.packer.pack_value({
            'upload_url': upload_url,
            'upload_token': upload_token,
        })

        log.webapi(log.API_CALL_POSTLARGEFILEPARTUPLOADURL_OK, {"cid": callid})
        return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/large-file-finish', methods=['POST'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_large_file_finish():

    request_pack = lib.packer.unpack_value(request.data)
    file_identifier = request_pack['file_identifier']
    b2_file_id = request_pack['file_id']
    sha1_list = request_pack['sha1_list']
    index_info_nonce = request_pack['index_info_pack']
    finish_large_file = request_pack['finish_large_file']

    callid = log.new_callid()
    log.webapi(log.API_CALL_POSTLARGEFILEFINISH, {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        album_rows = select_album_identifier_by_file_identifier(
            cursor, file_identifier)

        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEFINISH_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        album_identifier = album_rows[0].identifier

        album_rows = select_album(cursor, album_identifier)
        if len(album_rows) != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEFINISH_ERROR,
                {"cid": callid, "error": 400, "point": 2})
            return '', 400

        row = album_rows[0]

        if row.can_add_files != 1:
            log.webapi(log.API_CALL_POSTLARGEFILEFINISH_ERROR,
                {"cid": callid, "error": 400, "point": 3})
            return '', 400

        album_bucket_key_id = row.bucket_prefix_key_id
        album_bucket_key = adminapi.decrypt_album_prefix_bucket_key(row.id)
        album_bucket_prefix = row.album_bucket_prefix

        if album_bucket_key is None:
            log.webapi(
              log.API_CALL_POSTLARGEFILEFINISH_ERROR,
              {"cid": callid, "error": 400, "point": "decrypt_album_prefix_bucket_key"},
            )
            return '', 400

        if finish_large_file == 1:
            client = lib.b2.Client()
            client.authorize_account(album_bucket_key_id, album_bucket_key)
            file_name = album_bucket_prefix + "/" + file_identifier
            file_size = client.finish_large_file(b2_file_id, sha1_list)

            if file_size is None:
                log.webapi(log.API_CALL_POSTLARGEFILEFINISH_ERROR,
                    {"cid": callid, "error": 400, "point": 4})
                return '', 400

            pack = lib.packer.pack_value({
                'file_size': file_size,
            })
        else:
            file_name = request_pack["file_name"]
            file_size = request_pack["file_size"]

            pack = lib.packer.pack_value({
                'file_size': -1,
            })

        if is_own_file(cursor, file_identifier=file_identifier):
            query = """
                INSERT INTO
                    index_info (file_id, data_nonce, bucket_size, bucket_file_id, bucket_file_name)
                SELECT
                    id, %s, %s, %s, %s
                FROM
                    file
                WHERE
                    identifier = %s
                    AND user_id = %s
                    AND deleted IS NULL
            """

            cursor.execute(query, (index_info_nonce, file_size, b2_file_id, file_name,
                file_identifier, flask_login.current_user.row_id))

        else:
            query = """
                INSERT INTO
                    index_info (file_id, data_nonce, bucket_size, bucket_file_id, bucket_file_name)
                SELECT
                    f.id, %s, %s, %s, %s
                FROM
                    file f, shared_album sa, album a, album_file af
                WHERE
                    f.identifier = %s
                    AND f.creator_id = %s
                    AND f.id = af.file_id
                    AND af.album_id = sa.album_id
                    AND sa.email_to = %s
                    AND sa.can_add_files = 1
                    AND deleted IS NULL
            """

            cursor.execute(query, (index_info_nonce, file_size, b2_file_id, file_name,
                file_identifier, flask_login.current_user.row_id, flask_login.current_user.email))

        conn.commit()

        log.webapi(log.API_CALL_POSTLARGEFILEFINISH_OK, {"cid": callid})
        return response_from_pack(pack), 200


@apiv1_blueprint.route('/api/v1/file-index', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_file_index_get():

    file_identifier = request.args.get("file")

    callid = log.new_callid()
    log.webapi(log.API_CALL_GETFILEINDEX, {"cid": callid, "file": file_identifier})

    with lib.database.connect() as conn:
        cursor = lib.database.get_cursor(conn)

        index_info_rows = select_index_info(cursor, file_identifier)

        index_info_list = [{'data': r.data_nonce, 'bucket_size': r.bucket_size}
            for r in index_info_rows]

        pack = lib.packer.pack_value({
            'index_info': index_info_list,
        })

        log.webapi(log.API_CALL_GETFILEINDEX_OK, {"cid": callid})
        return response_from_pack(pack), 200

@apiv1_blueprint.route('/api/v1/file-ordering', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_file_ordering():
    "return max ordering value for current user"

    callid = log.new_callid()
    log.webapi(log.API_CALL_FILEORDERING, {"cid": callid})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        query = """
            SELECT MAX(ordering) max_ordering FROM file WHERE user_id = %s AND deleted IS NULL
        """

        c.execute(query, (flask_login.current_user.row_id, ))
        ordering_rows = c.fetchall()

        if len(ordering_rows) != 1:
            log.webapi(log.API_CALL_FILEORDERING_ERROR,
                {"cid": callid, "error": 400, "point": 1})
            return '', 400

        max_ordering = ordering_rows[0].max_ordering

        if max_ordering is None:
            max_ordering = 0

        log.webapi(log.API_CALL_FILEORDERING, {"cid": callid, "max": max_ordering})
        log.webapi(log.API_CALL_FILEORDERING_OK, {"cid": callid})

        return response_from_pack(lib.packer.pack_value({'max_ordering': max_ordering})), 200

@apiv1_blueprint.route('/api/v1/system-space', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@valid_subscription_required
def api_system_space():
    """return used/available/total system space"""

    callid = log.new_callid()
    log.webapi(log.API_CALL_SYSTEMSPACE, {"cid": callid})

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        test_env = app.config['MEDIASERVICE_ENV'] == "test"
        if test_env:
            max_system_storage_bytes = flask_login.current_user.max_storage_gb*1000*1000*100    # 100 MB in test
        else:
            max_system_storage_bytes = flask_login.current_user.max_storage_gb*1000*1000*1000   # 1000 MB in prod

        used_system_space_bytes = select_user_total_system_bucket_used_space_bytes(c)

        log.webapi(log.API_CALL_SYSTEMSPACE, {
            "cid": callid,
            "used": str(used_system_space_bytes),
            "avail": str(max_system_storage_bytes - used_system_space_bytes),
            "total": str(max_system_storage_bytes),
        })

        package = {
            "used_system_storage_bytes": str(used_system_space_bytes),
            "available_system_storage_bytes": str(max_system_storage_bytes - used_system_space_bytes),
            "total_system_storage_bytes": str(max_system_storage_bytes),
        }

        log.webapi(log.API_CALL_SYSTEMSPACE_OK, {"cid": callid})

        return response_from_pack(lib.packer.pack_value(package)), 200


@apiv1_blueprint.route('/api/v1/genta-analytics', methods=['POST'])
@lib.errors.exception_wrapper
def api_genta_analytics():
    log.gentaanalytics({"data": request.data.decode('utf8')})
    return '', 200

@apiv1_blueprint.route('/api/v1/ping', methods=['GET'])
@lib.errors.exception_wrapper
def api_ping():
    log.webapi(log.API_CALL_PING_OK, {})
    return '', 200

@apiv1_blueprint.route('/api/v1/user-feedback', methods=['POST'])
@lib.errors.exception_wrapper
def api_user_feedback():

    unpack = lib.packer.unpack_value(request.data)
    email = unpack['email'].lower()
    message = unpack['message']

    with lib.database.connect() as conn:
        c = lib.database.get_cursor(conn)

        query = """
            INSERT INTO user_feedback (email, message) VALUES (%s, %s)
        """

        c.execute(query, (email, message, ))
        conn.commit()

    return '', 200

@apiv1_blueprint.route('/api/v1/task', methods=['GET'])
@lib.errors.exception_wrapper
@flask_login.login_required
@trial_subscription_required
def api_background_task():

  task_id = request.args.get('id')
  user_id = flask_login.current_user.row_id

  callid = log.new_callid()
  log.webapi(log.API_CALL_TASK, {"cid": callid, "task_id": task_id})

  r = adminapi.get_task_status(user_id, task_id)

  if r.status_code != 200:
    log.webapi(log.API_CALL_TASK_ERROR, {"cid": callid, "status": r.status_code})
    return '', r.status_code

  log.webapi(log.API_CALL_TASK_OK, {"cid": callid})
  return response_from_pack(r.content), r.status_code
