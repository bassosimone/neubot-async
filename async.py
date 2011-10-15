
#
# Copyright (c) 2011 Simone Basso <bassosimone@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

'''
 Neubot async protocol model.

 To use Neubot protocol model you need to subclass Protocol and
 implement recv_complete(), send_complete() and connection_ready()
 according to your protocol needs.  Typically, you also want to
 invoke start_send() to start sending data.

 You typically pass the protocol constructor a dictionary that
 contains the protocol configuration.  The protocol class honours
 the following settings: ssl (boolean), keyfile (string) and
 certfile (string).  They are all used to configure SSL.

 This file also defines ProtocolSimple, which is a simpler class
 mainly used as a benchmark for protocol.
'''

#
# The main reason why I've written this file out of Neubot current
# stream implementation is because I would like to use it in a PhD
# course.  Additionally, it is an interesting exercise to reflect
# on sources of complexity (yes, I've reread Raymond recently).
# Finally, because this may be an interesting way to find simpler
# and possibly faster ways to implement Neubot stream.
#

import asyncore
import collections
import getopt
import logging
import os
import sched
import socket
import ssl
import sys
import time

# Maximum receive from a socket
RECV_MAX = 262144

# Maximum read from a file
READ_MAX = 4194304

#
# NOTE The problem with time.time() is that if the user
# changes radically the current time we cannot detect
# that and repair.  I am not sure whether such problem
# exists under Windows too, but I suspect it doesn't.
#
if os.name == 'nt':
    def ticks():
        ''' Return current time '''
        return time.clock()
else:
    def ticks():
        ''' Return current time '''
        return time.time()

class Poller(sched.scheduler):

    ''' I/O events dispatcher.  '''

    #
    # We basically use asyncore.poll as sched.scheduler's
    # delayfunc.  And we always register a 'periodic' event
    # that runs every 10 seconds, which by the way keeps
    # the scheduler alive.  The result is that the scheduler
    # invokes poll() with timeout equal to the amount of time
    # before the next periodic event.
    # The dispatcher model is the same as the one expected
    # by asyncore, except that we invoke periodically the
    # handle_periodic function, if defined.
    # To know the list of registered socket we peek at the
    # global asyncore.socket_map.
    #

    def __init__(self):
        ''' Initialize the poller '''
        self.again = True
        sched.scheduler.__init__(self, ticks, self.poll)
        self.periodic()

    def break_loop(self):
        ''' Break out of the event loop '''
        self.again = False

    def loop(self):
        ''' Event loop '''
        while self.again:
            try:
                self.run()
            except (KeyboardInterrupt, SystemExit):
                raise
            except:
                logging.error(asyncore.compact_traceback())

    def sched(self, delay, action, argument):
        ''' Schedule a new event '''
        return self.enter(delay, 0, action, argument)

    def unsched(self, event):
        ''' Deschedule an event '''
        self.cancel(event)

    def periodic(self, *argument):
        ''' Check whether timeout expired '''
        self.sched(10, self.periodic, argument)
        for protocol in list(asyncore.socket_map.values()):
            # Careful because it's not part of asyncore model
            if hasattr(protocol, 'handle_periodic'):
                protocol.handle_periodic()

    @staticmethod
    def poll(timeo):
        ''' Poll registered sockets for I/O events '''
        if asyncore.socket_map:
            asyncore.poll(timeo, asyncore.socket_map)
        else:
            time.sleep(timeo)

#
# Typically there is just one poller and users
# import and use it.
#
POLLER = Poller()

class Protocol(asyncore.dispatcher):

    ''' This class implements the complete protocol model, with
        support for SSL sockets '''

    def __init__(self, conf=None, sock=None, sock_map=None):
        ''' Generic protocol initializer '''
        asyncore.dispatcher.__init__(self, sock, sock_map)
        if not conf:
            conf = {}
        self._conf = conf
        self._outq = collections.deque()
        self._read_is_write = False
        self._read_is_handshake = False
        self._sslsock = None
        self._write_is_read = False
        self._write_is_handshake = False
        self.connect_time = 0

    #
    # - we always read the socket which means we are
    #   readily notified of a disconnection;
    # - there is NO input buffering at this level because
    #   that would be a source of EXTRA complexity;
    # - _read_is_handshake is True when the SSL handshake
    #   failed because of SSL_ERROR_WANT_READ;
    # - _read_is_write is True when a SSL write() failed
    #   with SSL_ERROR_WANT_READ because of a renegatiation;
    # - dispatcher.recv() is overriden to implement
    #   SSL read() operation.
    #

    def handle_read(self):
        ''' Invoked when the underlying socket is readable '''
        if self._read_is_handshake:
            self._read_is_handshake = False
            self._ssl_handshake()
        elif self._read_is_write:
            self._read_is_write = False
            self.handle_write()
        else:
            data = self.recv(RECV_MAX)
            if data:
                self.recv_complete(data)

    def recv_complete(self, data):
        ''' Override this method in subclasses '''

    def recv(self, maxlen):
        ''' Asynchronous socket recv '''
        if not self._sslsock:
            return asyncore.dispatcher.recv(self, maxlen)
        else:
            try:
                data = self._sslsock.read(maxlen)
                if not data:
                    self.handle_close()
                    return ''
                else:
                    return data
            except ssl.SSLError as why:
                if why.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    self._write_is_read = True
                    return ''
                elif why.args[0] == ssl.SSL_ERROR_WANT_READ:
                    return ''
                else:
                    raise

    #
    # - of course we don't want to be writable if we
    #   do not have nothing to send;
    # - _write_is_handshake is True when the SSL handshake
    #   failed because of SSL_ERROR_WANT_WRITE;
    # - _write_is_read is True when a SSL read() failed
    #   with SSL_ERROR_WANT_WRITE because of a renegatiation;
    # - we allow data to be a file because that is very
    #   handy to implement e.g. HTTP;
    # - for fairness each socket has the chance to
    #   perform JUST one single write;
    # - dispatcher.recv() is overriden to implement
    #   SSL read() operation.
    #

    def start_send(self, data):
        ''' Start asynchronous socket send '''
        self._outq.append(data)

    def writable(self):
        ''' Predicate for writability '''
        return (not self.accepting and not self.connected)      \
          or self._outq or self._write_is_read or               \
                self._write_is_handshake 

    def handle_write(self):
        ''' Invoked when the underlying socket is writable '''
        if self._write_is_handshake:
            self._write_is_handshake = False
            self._ssl_handshake()
        elif self._write_is_read:
            self._write_is_read = False
            self.handle_read()
        else:
            while self._outq:

                # Want to transfer N > 0 bytes of data
                if hasattr(self._outq[0], 'read'):
                    data = self._outq[0].read(READ_MAX)
                    if not data:
                        self._outq.popleft()
                        continue
                else:
                    data = self._outq.popleft()
                    if not data:
                        continue

                # Send and perform sanity checks
                count = self.send(data)
                if count < 0:
                    raise RuntimeError('Negative return value')
                if count > len(data):
                    raise RuntimeError('Too big return value')

                # Process result
                if count != len(data):
                    self._outq.appendleft(data[count:])
                self.send_complete(count)
                break

    def send_complete(self, count):
        ''' Override this method in subclasses '''

    def send(self, data):
        ''' Asynchronous socket send '''
        if not self._sslsock:
            return asyncore.dispatcher.send(self, data)
        else:
            try:
                return self._sslsock.write(data)
            except ssl.SSLError as why:
                if why.args[0] == ssl.SSL_ERROR_WANT_READ:
                    self._read_is_write = True
                    return 0
                elif why.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    return 0
                else:
                    raise

    #
    # - an additional source of complexity here is that we
    #   need to perform a nonblocking SSL handshake;
    # - here we calculate the time required to connect, which
    #   is used by all Neubot tests;
    # - I've decided that it's too convoluted to enforce
    #   here the restriction that no more than one connect()
    #   must be in progress at a time.
    #

    def connect(self, address):
        ''' Connect to the remote endpoint '''
        self.connect_time = ticks()
        asyncore.dispatcher.connect(self, address)

    def handle_connect(self):
        ''' Invoked when a new connection is established '''
        self.connect_time = ticks() - self.connect_time
        self.connection_nearly_ready(False)

    def handle_accept(self):
        ''' Invoked when a new connection is accepted '''
        result = self.accept()
        if result:
            proto = self.__class__(self._conf, result[0])
            # To catch SSL (and other) errors
            try:
                proto.connection_nearly_ready(True)
            except:
                proto.handle_error()

    def connection_nearly_ready(self, serverside):
        ''' Invoked when the connection is nearly ready '''
        if self._conf.get('ssl', False):
            if serverside:
                self._sslsock = ssl.SSLSocket(
                                              self.socket,
                                              keyfile=self._conf['keyfile'],
                                              certfile=self._conf['certfile'],
                                              server_side=True,
                                              do_handshake_on_connect=False
                                             )
                self._ssl_handshake()
            else:
                self._sslsock = ssl.SSLSocket(self.socket, server_side=False,
                                              do_handshake_on_connect=False)
                self._ssl_handshake()
        else:
            self.connection_ready()

    def _ssl_handshake(self):
        ''' Asynchronous SSL handshake '''
        try:
            self._sslsock.do_handshake()
        except ssl.SSLError as why:
            if why.args[0] == ssl.SSL_ERROR_WANT_READ:
                self._read_is_handshake = True
            elif why.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._write_is_handshake = True
            else:
                raise
        else:
            self.connection_ready()

    def connection_ready(self):
        ''' Override this method in subclasses '''

    #
    # The code here is written with in mind the common
    # case where the real protocol has nothing to do on
    # close().
    #

    def handle_error(self):
        ''' Invoked to handle errors '''
        logging.error(asyncore.compact_traceback())
        self.handle_close()

    def handle_close(self):
        ''' Override this method in subclasses '''
        self.close()

    def handle_periodic(self):
        ''' Override this method in subclasses '''

class ProtocolSimple(asyncore.dispatcher):

    ''' This class implements a simplified model without some
        bells and whistles '''

    #
    # In principle this class could be used, but it lacks
    # some nice features.
    # I keep it around because it provides a benchmark for
    # the real protocol class.
    #

    def __init__(self, conf=None, sock=None, sock_map=None):
        ''' Generic protocol initializer '''
        asyncore.dispatcher.__init__(self, sock, sock_map)
        if not conf:
            conf = {}
        self._conf = conf
        self._outq = collections.deque()

    def handle_read(self):
        ''' Invoked when the underlying socket is readable '''
        data = self.recv(RECV_MAX)
        if data:
            self.recv_complete(data)

    def recv_complete(self, data):
        ''' Override this method in subclasses '''

    def start_send(self, data):
        ''' Start asynchronous socket send '''
        self._outq.append(data)

    def writable(self):
        ''' Predicate for writability '''
        return (not self.accepting and not self.connected)      \
                       or self._outq

    # Just one write at a time, for fairness
    def handle_write(self):
        ''' Invoked when the underlying socket is writable '''
        data = self._outq.popleft()
        count = self.send(data)
        if count < len(data):
            self._outq.appendleft(data[count:])
        self.send_complete(count)

    def send_complete(self, count):
        ''' Override this method in subclasses '''

    def handle_connect(self):
        ''' Invoked when a new connection is established '''
        self.connection_ready()

    def handle_accept(self):
        ''' Invoked when a new connection is accepted '''
        result = self.accept()
        if result:
            proto = self.__class__(self._conf, result[0])
            # To catch SSL (and other) errors
            try:
                proto.connection_ready()
            except:
                proto.handle_error()

    def connection_ready(self):
        ''' Override this method in subclasses '''

    def handle_error(self):
        ''' Invoked to handle errors '''
        logging.error(asyncore.compact_traceback())
        self.handle_close()

    def handle_close(self):
        ''' Close the underlying socket '''
        self.close()

    def handle_periodic(self):
        ''' Override this method in subclasses '''

#PROTOCOL = ProtocolSimple
PROTOCOL = Protocol

class Server(PROTOCOL):

    ''' Simple echo server '''

    #
    # Usually the sender is faster than the receiver
    # so it's advisable to limit the amount of pending
    # data.  Which, by the way, makes the transfer
    # speed more stable.
    #

    pending = 0

    def readable(self):
        ''' Predicate for readability '''
        return self.pending < 4194304

    def recv_complete(self, data):
        ''' Some data has been received '''
        self.start_send(data)
        self.pending += len(data)

    def send_complete(self, count):
        ''' Invoked when a send operation completed '''
        self.pending -= count

class Client(PROTOCOL):

    ''' Simple echo client '''

    buffer = b'A' * RECV_MAX

    def connection_ready(self):
        ''' The connection has been established '''
        self.start_send(self.buffer)

    def recv_complete(self, data):
        ''' Some data has been received '''
        self.start_send(self.buffer)

    def handle_periodic(self):
        ''' Invoked periodically '''
        self.close()

def main(args):
    ''' Main function of this module '''

    try:
        options, arguments = getopt.getopt(args[1:], 'D:L')
    except getopt.error:
        sys.exit('Usage: protocol.py [-L] [-D name=value]')
    if arguments:
        sys.exit('Usage: protocol.py [-L] [-D name=value]')

    conf = {}
    listen = False
    for name, value in options:
        if name == '-D':
            name, value = value.split('=', 1)
            conf[name] = value
        elif name == '-L':
            listen = True

    if listen:
        server = Server(conf)
        server.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 8000))
        server.listen(10)
    else:
        client = Client(conf)
        client.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 8000))

    POLLER.loop()

if __name__ == '__main__':
    main(sys.argv)
