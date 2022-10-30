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

import json

from jwcrypto import jwt, jwk

from flask import current_app as app

# example from here:
# https://jwcrypto.readthedocs.io/en/stable/jwt.html

# generating a new key:
# >>> from jwcrypto import jwt, jwk
# >>> key = jwk.JWK(generate='oct', size=256)
# >>> key.export()  # doctest: +ELLIPSIS
# '{"k":"...","kty":"oct"}'

def encode_jwt(payload):
    key_json = app.config['MEDIASERVICE_JWT_KEY']
    key = jwk.JWK.from_json(key_json)
    token = jwt.JWT(
        header={"alg": "HS256"}, claims={"info": payload})
    token.make_signed_token(key)
    encrypted_token = jwt.JWT(
        header={"alg": "A256KW", "enc": "A256CBC-HS512"},
        claims=token.serialize())
    encrypted_token.make_encrypted_token(key)
    return encrypted_token.serialize()

def decode_jwt(encrypted_payload):
    key_json = app.config['MEDIASERVICE_JWT_KEY']
    key = jwk.JWK.from_json(key_json)
    et = jwt.JWT(key=key, jwt=encrypted_payload)
    st = jwt.JWT(key=key, jwt=et.claims)
    return json.loads(st.claims)["info"]
