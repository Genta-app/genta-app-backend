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

import requests

from flask import current_app as app

import lib.packer

def decrypt_bucket_key(bucket_row_id):
  sub_pack = lib.packer.pack_value({
    'row_id': bucket_row_id,
    'key_type': 0,
  })
  r = requests.post(
    app.config['ADMIN_LOCALAPI_URL'] + '/decrypt-bucket-key',
    data=sub_pack,
  )

  if r.status_code != 200:
    return None

  unpack = lib.packer.unpack_value(r.content)
  return unpack['bucket_key']


def decrypt_album_prefix_bucket_key(album_row_id):
  sub_pack = lib.packer.pack_value({
    'row_id': album_row_id,
    'key_type': 1,
  })
  r = requests.post(
    app.config['ADMIN_LOCALAPI_URL'] + '/decrypt-bucket-key',
    data=sub_pack,
  )

  if r.status_code != 200:
    return None

  unpack = lib.packer.unpack_value(r.content)
  return unpack['bucket_key']


def encrypt_bucket_key(bucket_key):
  sub_pack = lib.packer.pack_value({
      'bucket_key': bucket_key,
  })
  r = requests.post(
      app.config['ADMIN_LOCALAPI_URL'] + '/encrypt-bucket-key',
      data=sub_pack,
  )

  if r.status_code != 200:
      return None

  unpack = lib.packer.unpack_value(r.content)
  return unpack['encrypted_bucket_key']


def get_task_status(user_id, task_id):
  return requests.get(
    f'{app.config["ADMIN_API_URL"]}/task?id={task_id}&user_id={user_id}',
  )


def attach_new_bucket(user_id, master_key_id, master_key):
  pack = lib.packer.pack_value({
    'master_key_id': master_key_id,
    'master_key': master_key,
    'user_id': user_id,
  })

  return requests.post(
    app.config['ADMIN_API_URL'] + '/bucket',
    data=pack,
  )

