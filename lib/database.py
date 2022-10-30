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

import os

from flask import current_app as app

if 'DB_CONNECTOR' in os.environ:
    import mysql.connector as connector
else:
    import mariadb as connector

def connect():
    host = app.config['MEDIASERVICE_DATABASE_HOST']
    port = app.config['MEDIASERVICE_DATABASE_PORT']
    dbname = app.config['MEDIASERVICE_DATABASE_NAME']
    user = app.config['MEDIASERVICE_DATABASE_USER']
    passwd = app.config['MEDIASERVICE_DATABASE_PASSWORD']

    return connection_context(connector.connect(
        host=host,
        port=int(port),
        database=dbname,
        user=user,
        password=passwd))

def connect_log():
    host = app.config['MEDIASERVICE_LOG_DATABASE_HOST']
    port = app.config['MEDIASERVICE_LOG_DATABASE_PORT']
    dbname = app.config['MEDIASERVICE_LOG_DATABASE_NAME']
    user = app.config['MEDIASERVICE_LOG_DATABASE_USER']
    passwd = app.config['MEDIASERVICE_LOG_DATABASE_PASSWORD']

    return connection_context(connector.connect(
        host=host,
        port=int(port),
        database=dbname,
        user=user,
        password=passwd,
        autocommit=True))

def get_cursor(conn):
    return conn.cursor(named_tuple=True)

class connection_context:

    def __init__(self, conn):
        self.connection = conn

    def __enter__(self):
        return self.connection

    def __exit__(self, a1, a2, a3):
        self.connection.close()
