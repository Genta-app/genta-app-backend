#
# Copyright (c) 2022 Genta.app. All rights reserved.
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
