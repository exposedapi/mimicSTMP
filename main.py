#!/usr/bin/env python3
"""SMTP honeypot: fake SMTP server that logs connection activity and message bodies."""

import logging
import uuid
from datetime import datetime
from twisted.internet import reactor, defer
from twisted.internet.protocol import Factory
from twisted.internet.address import IPv4Address
from twisted.mail.smtp import SMTP

# Logging
logging.basicConfig(
    filename="smtp_honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
logging.getLogger("").addHandler(_console)
logger = logging.getLogger("smtp_honeypot")

# Configuration
SMTP_SERVER_NAME = "exposed.api.com"
WELCOME_BANNER = f"220 {SMTP_SERVER_NAME} ESMTP Postfix"


class HoneypotSMTPProtocol(SMTP):
    def __init__(self):
        super().__init__()
        self.session_id = str(uuid.uuid4())[:8]
        self.remote_ip = None
        self.host = SMTP_SERVER_NAME
        self.reset_session()

    def reset_session(self):
        self.sender = None
        self.recipients = []
        self.in_data_mode = False
        self.data_lines = []
        self.session_start = datetime.now()

    def greeting(self):
        return WELCOME_BANNER

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.remote_ip = peer.host if isinstance(peer, IPv4Address) else str(peer)
        logger.info(f"[{self.session_id}] New connection from: {self.remote_ip}")
        self.transport.write(f"{self.greeting()}\r\n".encode("ascii"))

    def connectionLost(self, reason=None):
        logger.info(f"[{self.session_id}] Connection closed from {self.remote_ip}")
        try:
            super().connectionLost(reason)
        except Exception:
            # ensure connectionLost doesn't raise for our honeypot
            pass

    def lineReceived(self, line):
        # DATA mode: collect message body until a single dot line
        if self.in_data_mode:
            try:
                line_str = line.decode("utf-8", errors="replace")
            except Exception:
                line_str = "<decoding-error>"
            # RFC5321: a line with a single dot ends DATA
            if line_str.strip() == ".":
                self.in_data_mode = False
                # Log captured message
                logger.info(
                    f"[{self.session_id}] Email completed | From: {self.sender} | "
                    f"To: {','.join(self.recipients)} | IP: {self.remote_ip}"
                )
                logger.info(f"[{self.session_id}] --- BEGIN MESSAGE ---")
                for l in self.data_lines:
                    logger.info(f"[{self.session_id}] {l}")
                logger.info(f"[{self.session_id}] --- END MESSAGE ---")
                self.transport.write(b"250 OK: Message accepted\r\n")
                self.data_lines = []
                self.reset_session()
                return
            self.data_lines.append(line_str.rstrip("\r\n"))
            return

        # Normal command processing
        try:
            line_str = line.decode("utf-8", errors="replace").strip()
        except Exception:
            line_str = "<decoding-error>"
        logger.debug(f"[{self.session_id}] Command: {line_str}")
        upper_line = line_str.upper()

        # Greetings
        if upper_line.startswith("HELO ") or upper_line.startswith("EHLO "):
            domain = line_str.split(" ", 1)[1] if " " in line_str else ""
            if upper_line.startswith("HELO "):
                logger.info(f"[{self.session_id}] HELO: {domain}")
                self.transport.write(
                    f"250 {SMTP_SERVER_NAME} Hello {self.remote_ip}, nice to meet you\r\n".encode("ascii")
                )
            else:
                logger.info(f"[{self.session_id}] EHLO: {domain}")
                self.transport.write(f"250-{SMTP_SERVER_NAME} Hello {self.remote_ip}\r\n".encode("ascii"))
                self.transport.write(b"250-SIZE 10485760\r\n")
                self.transport.write(b"250-ETRN\r\n")
                self.transport.write(b"250-STARTTLS\r\n")
                self.transport.write(b"250-ENHANCEDSTATUSCODES\r\n")
                self.transport.write(b"250-8BITMIME\r\n")
                self.transport.write(b"250 DSN\r\n")
            return

        # MAIL FROM
        if upper_line.startswith("MAIL FROM:"):
            sender = line_str[10:].strip()
            self.sender = sender
            logger.info(f"[{self.session_id}] MAIL FROM: {sender}")
            self.transport.write(b"250 Sender address accepted\r\n")
            return

        # RCPT TO
        if upper_line.startswith("RCPT TO:"):
            recipient = line_str[8:].strip()
            self.recipients.append(recipient)
            logger.info(f"[{self.session_id}] RCPT TO: {recipient}")
            self.transport.write(b"250 Recipient address accepted\r\n")
            return

        # DATA
        if upper_line == "DATA":
            logger.info(f"[{self.session_id}] DATA command received")
            self.in_data_mode = True
            self.data_lines = []
            self.transport.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            return

        # QUIT
        if upper_line == "QUIT":
            logger.info(f"[{self.session_id}] QUIT command received")
            self.transport.write(b"221 Bye\r\n")
            self.transport.loseConnection()
            return

        # Unknown command
        logger.info(f"[{self.session_id}] Unknown command: {line_str}")
        self.transport.write(b"500 Command not implemented\r\n")


class HoneypotFactory(Factory):
    protocol = HoneypotSMTPProtocol


if __name__ == "__main__":
    # Default port is 2525 to avoid requiring root. Set to 25 if you know what you're doing.
    PORT = 2525
    logger.info(f"Starting SMTP honeypot on port {PORT}")
    logger.info(f"Server will identify as {SMTP_SERVER_NAME}")
    reactor.listenTCP(PORT, HoneypotFactory())
    try:
        reactor.run()
    except KeyboardInterrupt:
        logger.info("SMTP honeypot shutting down")
        reactor.stop()
