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

import struct

TYPE_STRING = 1
# this type is written into some early prod files, but
# should not be used for encoding anymore
#TYPE_INT32  = 2
TYPE_BYTES  = 3
TYPE_LIST   = 4
TYPE_MAP    = 5
TYPE_INT64  = 6

PACK_FORMAT_VERSION = 42

def pack_value(value):
    return struct.pack(">i", PACK_FORMAT_VERSION) + _value_to_array(value)

def _value_to_array(value):
    t = type(value)

    if t == bytes:
        return _bytes_to_array(value)
    elif t == str:
        return _str_to_array(value)
    elif t == int:
        return _int_to_array(value)
    elif t == list:
        return _list_to_array(value)
    elif t == dict:
        return _dict_to_array(value)
    else:
        print(value, type(value))
        assert(False) # float?

def _bytes_to_array(value):
    """
       4 byte: TYPE_BYTES
       4 byte: length
     variable: value
    """
    return struct.pack(">i", TYPE_BYTES) + struct.pack(">i", len(value)) + value


def _str_to_array(value, encode_type=True):
    """
       4 byte: TYPE_STRING
       4 byte: byte length
     variable: value
    """
    b = value.encode("utf8")
    if encode_type:
        return struct.pack(">i", TYPE_STRING) + struct.pack(">i", len(b)) + b
    else:
        return struct.pack(">i", len(b)) + b


def _int_to_array(value):
    """
       4 byte: TYPE_INT64
       8 byte: value
    """
    return struct.pack(">i", TYPE_INT64) + struct.pack(">q", value)

def _list_to_array(value):
    """
       4 byte: TYPE_LIST
       4 byte: number of items
     variable: items
    """
    b = struct.pack(">i", TYPE_LIST) + struct.pack(">i", len(value))
    for item in value:
        b += _value_to_array(item)
    return b

def _dict_to_array(value):
    """
       4 byte: TYPE_DICT
       4 byte: number of items
     string value: name
     variable: items
    """
    b = struct.pack(">i", TYPE_MAP) + struct.pack(">i", len(value))
    for key in value:
        assert type(key) == str
        b += _str_to_array(key, encode_type=False)
        b += _value_to_array(value[key])
    return b

def _unpack_int32(arr):
    assert len(arr) >= 4
    return struct.unpack(">i", arr[:4])[0]

def _unpack_int64(arr):
    assert len(arr) >= 8
    return struct.unpack(">q", arr[:8])[0]

def unpack_value(arr):
    assert len(arr) >= 12
    format_version = _unpack_int32(arr)
    assert format_version == PACK_FORMAT_VERSION
    return _value_from_array(arr[4:])[0]

def _value_from_array(arr):
    t = _unpack_int32(arr)
    if t == TYPE_BYTES:
        value, sz = _bytes_from_array(arr[4:])
    elif t == TYPE_STRING:
        value, sz = _str_from_array(arr[4:])
    elif t == TYPE_INT64:
        value, sz = _int_from_array(arr[4:])
    elif t == TYPE_LIST:
        value, sz = _list_from_array(arr[4:])
    elif t == TYPE_MAP:
        value, sz = _dict_from_array(arr[4:])
    else:
        assert False # float?
    return value, sz + 4

def _bytes_from_array(arr):
    length = _unpack_int32(arr)
    value = arr[4:4 + length]
    assert length == len(value)
    return value, length + 4

def _str_from_array(arr):
    length = _unpack_int32(arr)
    value = arr[4:4 + length]
    assert length == len(value)
    return value.decode('utf8'), length + 4

def _int_from_array(arr):
    return _unpack_int64(arr), 8

def _list_from_array(arr):
    length = _unpack_int32(arr)

    offset = 4
    list_value = []

    for x in range(length):
        item, sz = _value_from_array(arr[offset:])
        list_value.append(item)
        offset += sz

    return list_value, offset


def _dict_from_array(arr):
    length = _unpack_int32(arr)

    offset = 4
    dict_value = {}

    for x in range(length):
        key, sz = _str_from_array(arr[offset:])
        offset += sz
        item, sz = _value_from_array(arr[offset:])
        offset += sz
        dict_value[key] = item

    return dict_value, offset


