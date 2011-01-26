from os import urandom

from twisted.protocols.stateful import StatefulProtocol
from twisted.python import log

from d3des import generate_response
from rfb import check_password

(
    STATE_VERSION,
    STATE_SECURITY_TYPES,
    STATE_AUTHENTICATION,
    STATE_RESULT,
    STATE_CONNECTED
) = range(5)

class VNCAuthenticator(StatefulProtocol):
    """
    Base class for VNC protocols.

    This protocol isn't interesting on its own; subclass it to make a server
    or client.
    """

    VERSION = "RFB 003.008\n"

    def __init__(self, password):
        self.password = password

    def authenticated(self):
        """
        Switch to proxy mode.
        """

        log.msg("Successfully authenticated!")

class VNCServerAuthenticator(VNCAuthenticator):
    """
    Trivial server protocol which can authenticate VNC clients.

    This protocol is lacking lots of things, like support for older VNC
    protocols.
    """

    def connectionMade(self):
        self.transport.write(self.VERSION)

    def getInitialState(self):
        return self.check_version, 12

    def check_version(self, version):
        if version == self.VERSION:
            log.msg("Checked version!")
            self.transport.write("\x02\x01\x02")
            return self.select_security_type, 1
        else:
            log.err("Can't handle VNC version %s" % version)
            self.transport.loseConnection()

    def select_security_type(self, security_type):
        """
        Choose the security type that the client wants.
        """
        log.msg("trace pick_security_types")

        security_type = ord(security_type)

        if security_type == 2:
            # VNC authentication. Issue our challenge.
            self.challenge = urandom(16)
            self.transport.write(self.challenge)

            return self.vnc_authentication_result, 16
        elif security_type == 1:
            # No authentication. Just move to the SecurityResult.
            self.authenticated()
        else:
            log.err("Couldn't agree on an authentication scheme!")
            self.transport.loseConnection()

    def vnc_authentication_result(self, response):
        log.msg("Doing VNC auth, buf %r" % response)

        if check_password(self.challenge, response, self.password):
            self.authenticated()
        else:
            log.err("Failed VNC auth!")
            self.transport.loseConnection()

    def authenticated(self):
        self.transport.write("\x00\x00\x00\x00")
        VNCAuthenticator.authenticated(self)

class VNCClientAuthenticator(VNCAuthenticator):
    """
    Trivial client protocol which can authenticate itself to a VNC server.

    This protocol is lacking lots of things, like support for older VNC
    protocols.
    """

    def getInitialState(self):
        return self.check_version, 12

    def check_version(self, version):
        if version == self.VERSION:
            log.msg("Checked version!")
            self.transport.write(self.VERSION)
            return self.count_security_types, 1
        else:
            log.err("Can't handle VNC version %s" % version)
            self.transport.loseConnection()

    def count_security_types(self, data):
        count = ord(data)

        if not count:
            log.err("Server wouldn't give us any security types!")
            self.transport.loseConnection()

        return self.pick_security_type, count

    def pick_security_type(self, data):
        """
        Ascertain whether the server supports any security types we might
        want.
        """

        security_types = set(ord(i) for i in data)
        if 2 in security_types:
            log.msg("Choosing VNC authentication...")
            self.transport.write("\x02")
            return self.vnc_authentication, 16
        elif 1 in security_types:
            log.msg("Choosing no authentication...")
            self.transport.write("\x01")
            return self.security_result, 4
        else:
            log.err("Couldn't agree on an authentication scheme!")
            self.transport.loseConnection()

    def vnc_authentication(self):
        # Take in 16 bytes, encrypt with 3DES using the password as the key,
        # and send the response.
        if len(self.buf) < 16:
            return

        challenge, self.buf = self.buf[:16], self.buf[16:]

        response = generate_response(self.password, challenge)
        self.transport.write(response)

        return self.security_result, 4

    def security_result(self, data):
        if data == "\x00\x00\x00\x01":
            # Success!
            self.authenticated()
        else:
            log.err("Failed security result!")
            self.transport.loseConnection()
