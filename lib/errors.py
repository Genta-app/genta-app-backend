#
# Copyright (c) 2022 Genta.app. All rights reserved.
#

import sys
import json
import traceback
from functools import wraps

import lib.logging as log

def exception_wrapper(handler):

    @wraps(handler)
    def wrapper(*args, **kwargs):
        try:
            return handler(*args, **kwargs)
        except:
            exc = traceback.format_exc()
            log.webapi(log.API_CALL_EXCEPTION, {"backtrace": exc})
            print(exc)
            return '', 401
    return wrapper
