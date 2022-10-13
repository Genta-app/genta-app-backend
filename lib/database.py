#
# Copyright (c) 2022 Genta.app. All rights reserved.
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
