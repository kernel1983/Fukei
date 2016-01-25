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


class LocalConnection(object):
    COMMAND_MAP = {
        0x01:   'CONNECT',
        0x02:   'BIND',
        0x03:   'UDP ASSOCIATION'
    }
    ACCEPTED_COMMANDS = [0x01, ]
    ADDRESS_TYPE_MAP = {
        0x01:   'IPv4 Address',
        0x03:   'Domain name',
        0x04:   'IPv6 Address'
    }
    ADDRESS_TYPE_LENGTH = {
        0x01:   4,
        0x04:   16
    }
    ACCEPTED_ADDRESS_TYPES = [0x01, 0x03, 0x04]
    REPLY_CODES = {
        0x00:   'succeeded',
        0x01:   'general SOCKS server failure',
        0x02:   'connection not allowed by ruleset',
        0x03:   'Network unreachable',
        0x04:   'Host unreachable',
        0x05:   'Connection refused',
        0x06:   'TTL expired',
        0x07:   'Command not supported',
        0x08:   'Address type not supported',
        0x09:   "to X'FF' unassigned"
    }
    ERRNO_MAP = {
        errno.ECONNREFUSED:     0x05,
        errno.EHOSTUNREACH:     0x04,
        errno.ENETUNREACH:      0x03,
    }

    def __init__(self, stream, address, upstream_cls=None):
        self.stream = stream
        self.addr = address
        if upstream_cls is None:
            raise TypeError('a upstream is necessary')
        self.upstream_cls = upstream_cls
        self.stream.set_close_callback(self.on_connection_close)
        self.dest = None
        self.on_connected()

    def on_connected(self):
        logger.debug('start connect...')
        self.cmd = 0x01
        self.atyp = 0x03
        self.domain_name = self.addr[0]
        self.raw_dest_addr = struct.pack("!B", len(self.addr[0])) + self.addr[0]
        self.raw_dest_port = struct.pack("!H", self.addr[1])
        self.dest = self.addr
        self.do_connect()

    def on_connection_close(self):
        logger.debug("disconnected!")
        self.clean_upstream()

    def wait_for_domain_name(self):
        self.raw_dest_addr = ""
        self.stream.read_bytes(1, self.on_domain_name_num_octets)

    def on_domain_name_num_octets(self, data):
        self.raw_dest_addr += data
        num, = struct.unpack("!B", data)
        self.stream.read_bytes(num, self.on_domain_name_octets)

    def on_domain_name_octets(self, data):
        self.raw_dest_addr += data
        self.domain_name = data
        self.on_domain_name_complete()

    def on_domain_name_complete(self):
        logger.debug("parsed domain name: %s" % self.domain_name)
        self.dest_addr = self.domain_name
        self.wait_destination_port()

    def do_connect(self):
        config = Config.current()

        logger.debug("server : %s, %s" % (config.server, config.server_port))
        logger.debug("server dest: %s, %s" % self.dest)
        dest = (config.server, config.server_port)
        self.upstream = self.upstream_cls(dest, socket.AF_INET,
                    self.on_upstream_connect, self.on_upstream_error,
                    self.on_upstream_data, self.on_upstream_close)

    # def client_close(self, data=None):
    #     print data
    #     if not self.upstream:
    #         return
    #     if data:
    #         self.upstream.write(data)
    #     self.upstream.close()
    #
    # def read_from_client(self, data):
    #     # print "read_from_client", data
    #     self.upstream.write(data)

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

def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)

def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port

def fetch_request(url, callback, **kwargs):
    proxy = get_proxy(url)
    if proxy:
        logger.debug('Forward request via upstream proxy %s', proxy)
        tornado.httpclient.AsyncHTTPClient.configure(
            'tornado.curl_httpclient.CurlAsyncHTTPClient')
        host, port = parse_proxy(proxy)
        kwargs['proxy_host'] = host
        kwargs['proxy_port'] = port

    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback, raise_error=False)

class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def compute_etag(self):
        return None # disable tornado Etag

    @tornado.web.asynchronous
    def get(self):
        print
        print self.request.method, self.request.uri.replace(self.request.protocol+"://"+self.request.host, ""), self.request.version
        print "\n".join(["%s: %s" % (i, j) for i, j in self.request.headers.items()])
        # print self.request.connection._request_headers
        logger.debug('Handle %s request to %s', self.request.method,
                     self.request.uri)

        def handle_response(response):
            if (response.error and not
                    isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code, response.reason)
                self._headers = tornado.httputil.HTTPHeaders() # clear tornado default header

                for header, v in response.headers.get_all():
                    if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                        self.add_header(header, v) # some header appear multiple times, eg 'Set-Cookie'

                if response.body:
                    self.set_header('Content-Length', len(response.body))
                    self.write(response.body)
            self.finish()

        body = self.request.body
        if not body:
            body = None
        try:
            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']
            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method, body=body,
                headers=self.request.headers, follow_redirects=False,
                allow_nonstandard_methods=True)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        # print self.request.method, self.request.headers.items()
        # print self.request.body
        logger.debug('Start CONNECT to %s', self.request.uri)
        host, port = self.request.uri.split(':')
        connection = LocalConnection(self.request.connection.stream, (host, int(port)), fukei.upstream.local.LocalUpstream)



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
