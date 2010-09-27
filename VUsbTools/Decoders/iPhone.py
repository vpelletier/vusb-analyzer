#
# VUsbTools.Decoders.iPhone
# Micah Elizabeth Scott <micah@vmware.com>
#
# Decodes the usbmuxd protocol used by iPhone and iPod Touch devices.
# Based on protocol information from marcan's open source usbmuxd
# implementation at http://marcansoft.com/blog/iphonelinux/usbmuxd/
#
# Copyright (C) 2010 VMware, Inc. Licensed under the MIT
# License, please see the README.txt. All rights reserved.
#

import plistlib
import struct
from VUsbTools import Decode, Struct, Types


def isascii(s):
    for c in s:
        if ord(c) < 32 or ord(c) > 126:
            return False
    return True


class USBMuxDecoder:
    """Decodes incoming or outgoing usbmuxd bulk plackets."""

    ipProto = Struct.EnumDict({
        0: 'VERSION',
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        })

    portNumbers = Struct.EnumDict({
        62078: 'lockdownd',
        })

    remainingLength = 0
    lockdownBuffer = ""

    def handleEvent(self, event):
        if not event.isDataTransaction():
            return

        if self.remainingLength == 0:
            # Beginning a new packet
            self.handleGenericPacket(event)

        elif self.remainingLength >= event.datalen:
            # Continuing a packet
            self.remainingLength -= event.datalen
            event.pushDecoded("[usbmuxd continuation, %d bytes left]" %
                              self.remainingLength)

        else:
            event.pushDecoded("[usbmuxd ERROR, only expected %d bytes]" %
                              self.remainingLength)
            self.remainingLength = 0

    def handleGenericPacket(self, event):
        """Decode the usbmuxd header."""

        muxHeader = Struct.Group(None,
                                 Struct.UInt32BE("protocol"),
                                 Struct.UInt32BE("length"))

        data = muxHeader.decode(event.data)
        description = "iPhone usbmuxd: "

        if muxHeader.length is None:
            description += "ERROR"

        else:
            self.remainingLength = muxHeader.length - event.datalen
            description += "proto=%s len=0x%04x" % (self.ipProto[muxHeader.protocol],
                                              muxHeader.length)
            if self.remainingLength:
                description += " (0x%04x remaining)" % self.remainingLength

        event.pushDecoded(description)

        if self.ipProto[muxHeader.protocol] == 'TCP':
            self.handleTCP(event, data, muxHeader.length - 0x08)

    def handleTCP(self, event, data, datalen):
        """Decode an IPPROTO_TCP packet header, and log the payload."""

        datalen -= 0x14
        tcpHeader = Struct.Group(None,
                                 Struct.UInt16BEHex("source"),
                                 Struct.UInt16BEHex("dest"),
                                 Struct.UInt32BE("seq"),
                                 Struct.UInt32BE("ack_seq"),
                                 Struct.UInt16BEHex("flags"),
                                 Struct.UInt16BE("window"),
                                 Struct.UInt16BEHex("checksum"),
                                 Struct.UInt16BEHex("urg_ptr"))
        data = tcpHeader.decode(data)

        event.pushDecoded("iPhone TCP [%s -> %s] len=0x%04x" % (
            self.portNumbers[tcpHeader.source],
            self.portNumbers[tcpHeader.dest],
            datalen,
            ))

        event.appendDecoded("\nTCP Header:\n%s" % str(tcpHeader))
        event.appendDecoded("\nTCP Payload:\n%s" % Types.hexDump(data))

        # Look for a protocol-specific handler
        for port in tcpHeader.source, tcpHeader.dest:
            fn = getattr(self, "port_%s" % self.portNumbers[port], None)
            if fn:
                fn(event, data, datalen)

    def port_lockdownd(self, event, data, datalen):
        """Handle lockdownd packets. These form a stream, which may or
           may not line up with the underlying USB packets. Each
           lockdownd packet is an XML plist, prefixed with a 32-bit
           length.
           """
        summary = []
        self.lockdownBuffer += data

        if datalen == 0:
            # Leave the TCP decoder at the top of the stac
            return

        elif datalen != len(data):
            # Nothing we can reliably do without the whole log.
            self.lockdownBuffer = ""
            summary.append("ERROR, incomplete log!")

        elif (len(self.lockdownBuffer) >= 10 and
              self.lockdownBuffer[0] == '\0' and
              isascii(self.lockdownBuffer[1:])):
            # I haven't seen this documented, but sometimes lockdownd sends
            # ASCII error messages that are prefixed with one NUL byte.
            summary.append("Message, %r" % self.lockdownBuffer[1:])

        elif len(self.lockdownBuffer) >= 10 and self.lockdownBuffer[4:9] != "<?xml":
            # Something else that isn't a plist?
            self.lockdownBuffer = ""
            summary.append("UNRECOGNIZED (SSL encrypted?)")

        else:
            # Decode all the packets we can

            while len(self.lockdownBuffer) >= 4:
                length = struct.unpack(">I", self.lockdownBuffer[:4])[0]
                if len(self.lockdownBuffer) < length + 4:
                    break
                packet = self.lockdownBuffer[4:length + 4]
                self.lockdownBuffer = self.lockdownBuffer[length + 4:]

                event.appendDecoded("\nComplete lockdownd packet:\n%s" %
                                    Types.hexDump(packet))

                kvFull = []
                kvAbbrev = []

                for k, v in plistlib.readPlistFromString(packet).items():
                    kvFull.append("  %s = %s" % (k, v))

                    if isinstance(v, plistlib.Data):
                        v = "(data)"
                    elif isinstance(v, dict):
                        v = "(dict)"

                    kvAbbrev.append("%s=%s" % (k, v))

                event.appendDecoded("\nDecoded plist:\n%s" % "\n".join(kvFull))
                summary.append("{%s}" % " ".join(kvAbbrev))

        event.pushDecoded("lockdownd: %s" % (" ".join(summary) or "fragment"))


def detector(context):
    if (context.interface and context.endpoint and
        context.device.idVendor == 0x05ac and
        context.device.idProduct >= 0x1290 and
        context.device.idProduct <= 0x12A0 and
        context.interface.bInterfaceClass == 0xFF and
        context.interface.bInterfaceSubClass == 0xFE and
        context.interface.bInterfaceProtocol == 2 and
        context.endpoint.bmAttributes == 2
        ):
        return USBMuxDecoder()
