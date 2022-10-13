#
# Copyright (c) 2022 Genta.app. All rights reserved.
#

from flask import redirect, render_template, Blueprint, request, send_from_directory, send_file
index_blueprint = Blueprint('index', __name__)

import flask
import werkzeug

import lib.logging as log

@index_blueprint.route('/')
def redirect_to_index():
    return redirect("/index.html", 301)

@index_blueprint.route('/index.<string:filehash>.<string:ext>')
def index_hashed_static_resource(filehash, ext):
    return send_from_directory("modules/public", "index.%s.%s" % (filehash, ext, ))

@index_blueprint.route('/dl.<string:filehash>.<string:ext>')
def dl_hashed_static_resource(filehash, ext):
    return send_from_directory("modules/public", "dl.%s.%s" % (filehash, ext, ))

#@index_blueprint.route('/index.html')
#@index_blueprint.route('/signup')
#@index_blueprint.route('/signup/<string:email>')
#@index_blueprint.route('/login')
#@index_blueprint.route('/logout')
#@index_blueprint.route('/buckets')
#@index_blueprint.route('/account')
#@index_blueprint.route('/albums')
#@index_blueprint.route('/upload')
#@index_blueprint.route('/subscription')
#@index_blueprint.route('/subscription/<string:option>')
#@index_blueprint.route('/upload/<string:album>')
#@index_blueprint.route('/view/<string:album>')
#@index_blueprint.route('/view/<string:album>/')
#@index_blueprint.route('/view/<string:album>/<int:yyyymm>')
#def index_static_page_html(album=None, yyyymm=None, email=None, option=None):
#    resp = send_from_directory("modules/public", "index.html")
#    log.webpage(resp.status)
#    return resp

@index_blueprint.route('/stream.js')
def index_static_page_html_():
   resp = send_from_directory("modules/public/stream/", "stream.js")
   log.webpage(resp.status)
   return resp



@index_blueprint.route('/index.html')
#@index_blueprint.route('/signup')
@index_blueprint.route('/apply')
#@index_blueprint.route('/signup/<string:email>')
@index_blueprint.route('/signup/<string:email>/<string:email_code>')
@index_blueprint.route('/album/<string:email>')
@index_blueprint.route('/login')
@index_blueprint.route('/logout')
@index_blueprint.route('/storage')
@index_blueprint.route('/storage/<string:bucket>')
@index_blueprint.route('/account')
@index_blueprint.route('/account/upgrade')
@index_blueprint.route('/account/upgrade/success')
@index_blueprint.route('/account/upgrade/failure')
@index_blueprint.route('/upload')
@index_blueprint.route('/sub')
@index_blueprint.route('/sub/<string:option>')
@index_blueprint.route('/upload/<string:album>')
@index_blueprint.route('/view')
@index_blueprint.route('/view/<string:album>/')
@index_blueprint.route('/view/<string:album>/<int:yyyymm>')
@index_blueprint.route('/zoom/<string:album>')
@index_blueprint.route('/doc/information-policy')
@index_blueprint.route('/doc/attach-backblaze-storage')
@index_blueprint.route('/doc/privacy-policy')
@index_blueprint.route('/doc/tos')
def index_static_page_html(album=None, bucket=None, yyyymm=None, email=None, email_code=None, option=None):
    resp = send_from_directory("modules/public", "index.html")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/dl/<string:link_key>')
def direct_link_viewer_static_page_html(link_key=None):
    resp = send_from_directory("modules/public", "dl.html")
    log.webpage(resp.status)
    return resp

#@index_blueprint.route('/new.html')
#def new_static_page_html():
#    return send_from_directory("modules/public", "new.html")

# @index_blueprint.route('/privacy-policy')
# def privacy_policy_html():
#     resp = send_from_directory("modules/public", "privacy-policy", mimetype='text/html')
#     log.webpage(resp.status)
#     return resp

# @index_blueprint.route('/terms-of-service')
# def terms_of_service_html():
#     resp = send_from_directory("modules/public", "terms-of-service", mimetype='text/html')
#     log.webpage(resp.status)
#     return resp

@index_blueprint.route('/<string:image>.jpg')
def index_static_image_jpg(image):
    resp = send_from_directory("modules/public", image + ".jpg")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/assets/<string:image>.png')
def index_static_assets_image_png(image):
    resp = send_from_directory("modules/public/assets", image + ".png")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/<string:image>.<string:imagehash>.jpg')
def index_static_assets_hashed_image_jpg(image, imagehash):
    resp = send_from_directory("modules/public", image + "." + imagehash + ".jpg")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/<string:image>.<string:imagehash>.png')
def index_static_assets_hashed_image_png(image, imagehash):
    resp = send_from_directory("modules/public", image + "." + imagehash + ".png")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/assets/<string:image>.gif')
def index_static_assets_image_gif(image):
    resp = send_from_directory("modules/public/assets", image + ".gif")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/css/<string:stylesheet>.css')
def index_static_css(stylesheet):
    resp = send_from_directory("modules/public/css", stylesheet + ".css")
    log.webpage(resp.status)
    return resp

@index_blueprint.route('/js/<string:script>.js')
def index_static_js(script):
    resp = send_from_directory("modules/public/js", script + ".js")
    log.webpage(resp.status)
    return resp

# @index_blueprint.route('/<string:font>.<string:filehash>.woff')
# def index_static_font_woff(font, filehash):
#     resp = send_from_directory("modules/public/", "%s.%s.woff" % (font, filehash))
#     log.webpage(resp.status)
#     return resp

@index_blueprint.route('/<string:font>.woff2')
def index_static_font_woff2(font):
    resp = send_from_directory("modules/public/", f"{font}.woff2")
    log.webpage(resp.status)
    return resp

# we need this to send the right MIME type, otherwise browser refuses to compile
#@index_blueprint.route('/api.wasm', methods=['GET'])
#def index_wasm_api():
#    return send_file('modules/public/api.wasm', 'application/wasm')
