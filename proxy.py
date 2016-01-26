#!/usr/bin/env python
#
# Simple asynchronous HTTP proxy with tunnelling (CONNECT).
#
# GET/POST proxying based on
# http://groups.google.com/group/python-tornado/msg/7bea08e7a049cf26
#
# Copyright (C) 2012 Senko Rasic <senko.rasic@dobarkod.hr>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import logging
import os
import sys
import socket
import struct
import errno
import functools
from urlparse import urlparse

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.httputil

import fukei.upstream.local
from fukei.config import Config
from fukei import crypto

logger = logging.getLogger('tornado_proxy')

__all__ = ['ProxyHandler', 'run_proxy']


class LocalConnectionHttps(object):
    def __init__(self, stream, address, upstream_cls):
        self.stream = stream
        self.addr = address
        self.upstream_cls = upstream_cls
        self.stream.set_close_callback(self.on_connection_close)
        self.dest = None
        self.on_connected()

    def on_connected(self):
        logger.debug('start connect...')
        self.atyp = 0x03
        self.raw_dest_addr = struct.pack("!B", len(self.addr[0])) + self.addr[0]
        self.raw_dest_port = struct.pack("!H", self.addr[1])
        self.dest = self.addr
        self.do_connect()

    def on_connection_close(self):
        logger.debug("disconnected!")
        self.clean_upstream()

    def do_connect(self):
        config = Config.current()

        logger.debug("server : %s, %s" % (config.server, config.server_port))
        logger.debug("server dest: %s, %s" % self.dest)
        dest = (config.server, config.server_port)
        self.upstream = self.upstream_cls(dest, socket.AF_INET,
                    self.on_upstream_connect, self.on_upstream_error,
                    self.on_upstream_data, self.on_upstream_close)

    def on_upstream_connect(self, _dummy):
        config = Config.current()
        self.write_request()
        on_finish = functools.partial(self.on_socks_data, finished=True)
        self.stream.read_until_close(on_finish, self.on_socks_data)
        self.stream.write(b'HTTP/1.0 200 Connection established\r\n\r\n')
        # self.stream.read_until_close(self.client_close, self.read_from_client)

    def write_request(self, data=None):
        logger.debug('wait request...')
        address_type = self.atyp
        if data is None:
            if self.dest:
                data = self.raw_dest_addr + self.raw_dest_port
            else:
                data = struct.pack("!BLH", 0x01, 0x00, 0x00)
        else:
            if self.atyp == 0x03:
                address_type = 0x01
        self.upstream.write(struct.pack("!B", address_type) + data)

    def on_upstream_error(self, _dummy, no):
        logger.debug("upstream error: %s" % no)
        self.stream.close()

    def on_upstream_data(self, _dummy, data, finished=False):
        try:
            self.stream.write(data)
            logger.debug("recevied %d bytes of data from upstream." %
                         len(data))
        except IOError as e:
            logger.debug("cannot write: %s" % str(e))
            if self.upstream:
                self.upstream.close()
        if finished:
            self.on_connected()

    def on_upstream_close(self, _dummy=None):
        self.stream.close()
        logger.debug("upstream closed.")
        self.clean_upstream()

    def clean_upstream(self):
        if getattr(self, "upstream", None):
            self.upstream.close()
            self.upstream = None

    def on_socks_data(self, data, finished=False):
        if not self.upstream:
            return
        if data:
            self.upstream.write(data)
            logger.debug("sent %d bytes of data to upstream." %
                         len(data))

class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def compute_etag(self):
        return None # disable tornado Etag

    def on_connect(self):
        data = self.raw_dest_addr + self.raw_dest_port
        self.upstream.write(struct.pack("!B", 0x03) + data)

        data = "%s %s %s\r\n" % (self.request.method, self.request.uri.replace(self.request.protocol+"://"+self.request.host, ""), self.request.version)
        data += "\r\n".join(["%s: %s" % (i, j) for i, j in self.request.headers.items()])+"\r\n\r\n"
        self.upstream.write(data)
        # print self.request.body
        self.upstream.write(self.request.body)
        self.upstream.read_until('\r\n\r\n', self.on_headers)

    def on_headers(self, data):
        lines = data.split("\r\n")
        # print lines[0]
        self.request.connection.stream.write("%s\r\n" % lines[0])

        headers_data = "\r\n".join(lines[1:])
        # print headers_data
        self._headers = tornado.httputil.HTTPHeaders() # clear tornado default header
        headers = tornado.httputil.HTTPHeaders.parse(headers_data)
        for key, value in headers.get_all():
            self.request.connection.stream.write("%s: %s\r\n" % (key, value))
        self.request.connection.stream.write("\r\n")

        self.upstream.read_until_close(self.on_upstream_close, self.on_upstream_data)
        self.request.finish()

    def on_upstream_data(self, data):
        try:
            self.request.connection.stream.write(data)
            logger.debug("recevied %d bytes of data from upstream." %
                         len(data))
        except IOError as e:
            logger.debug("cannot write: %s" % str(e))
            if self.upstream:
                self.upstream.close()

    def on_upstream_close(self, _dummy=None):
        self.request.finish()
        logger.debug("upstream closed.")
        self.clean_upstream()

    def clean_upstream(self):
        if getattr(self, "upstream", None):
            self.upstream.close()
            self.upstream = None

    def on_upstream_error(self, _dummy, no):
        logger.debug("upstream error: %s" % no)
        # self.upstream.close()
        self.request.finish()

    def on_close(self):
        if self.upstream and self.upstream.error:
            self.on_upstream_error(self, self.upstream.error)
        else:
            self.on_upstream_close(self)

    @tornado.web.asynchronous
    def get(self):
        # print self.request.connection._request_headers
        logger.debug('Handle %s request to %s', self.request.method,
                     self.request.uri)

        addr = self.request.host.split(':')
        if len(addr) == 2:
            host, port = addr
        else:
            host, port = self.request.host, "80"

        self.addr = host, int(port)
        self.raw_dest_addr = struct.pack("!B", len(self.addr[0])) + self.addr[0]
        self.raw_dest_port = struct.pack("!H", self.addr[1])
        dest = (config.server, config.server_port)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.upstream = fukei.upstream.local.CryptoIOStream(self.socket)
        self.upstream.set_close_callback(self.on_close)
        self.upstream.connect(dest, self.on_connect)


    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        logger.debug('Start CONNECT to %s', self.request.uri)
        host, port = self.request.uri.split(':')
        connection = LocalConnectionHttps(self.request.connection.stream, (host, int(port)), fukei.upstream.local.LocalUpstream)


if __name__ == '__main__':
    config_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__))), 'config', 'config.json')
    config = Config.current(config_path)
    crypto.setup_table(config.password, config.method)

    from fukei.utils import log_config
    log_config('FukeiLocal', config.debug)

    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ], debug=config.debug)

    app.listen(config.local_port)
    # print ("Starting HTTP proxy on port %d" % config.local_port)
    tornado.ioloop.IOLoop.instance().start()
