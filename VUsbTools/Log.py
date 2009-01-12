#
# VUsbTools.Log
# Micah Dowty <micah@vmware.com>
#
# Implements parsers for USB log files. Currently
# this includes slurping usbAnalyzer data out of the
# VMX log, and parsing the XML logs exported by
# Ellisys Visual USB.
#
# Copyright (C) 2005-2009 VMware, Inc. Licensed under the MIT
# License, please see the README.txt. All rights reserved.
#

from __future__ import division
import sys, time, re, math, os, string, atexit
import xml.sax, Queue, threading, difflib
import gtk, gobject
import traceback, gzip, struct
from VUsbTools import Types


class UsbIOParser(Types.psyobj):
    """Parses USBIO log lines and generates Transaction objects appropriately.
       Finished transactions are pushed into the supplied queue.
       """
    lineOriented = True

    def __init__(self, completed):
        self.current = Types.Transaction()
        self.completed = completed

    def parse(self, line, timestamp=None, frame=None, lineNumber=None):
        tokens = line.split()
        finished = None

        if tokens[0] in ('Up', 'Down'):
            self.flush()
            self.current.dir = tokens[0]
            self.current.timestamp = timestamp
            self.current.frame = frame
            self.current.lineNumber = lineNumber
            self.parseKeyValuePairs(tokens[1:])

        # new Log_HexDump() format:
        # USBIO:  000: 80 06 ......
        elif len(tokens) >= 2 and len(tokens[0]) == 4 and len(tokens[1]) == 2:
            data = line.split(':')
            data = data[1].lstrip()
            self.current.appendHexData(data[:48])

        # old Log_HexDump() format:
        # USBIO: 80 06 ......
        elif len(tokens[0]) == 2:
            self.current.appendHexData(line[:48])

        else:
            self.flush()
            self.current.appendDecoded(line.strip())

    def parseKeyValuePairs(self, tokens):
        for token in tokens:
            kv = token.split('=', 1)
            if len(kv) > 1:
                if kv[0] in ('endpt'):
                    base = 16
                else:
                    base = 10
                setattr(self.current, kv[0], int(kv[1], base))

    def flush(self):
        """Force any in-progress transactions to be completed. This should be
           called when you know the USB analyzer is finished outputting
           data, such as when a non-USBIO line appears in the log.
           """
        if self.current.dir:
            self.completed.put(self.current)
            self.current = Types.Transaction()


class TimestampLogParser:
    """Parse a simple format which logs timestamps in nanosecond resolution.
       Lines are of the form:
          <timestamp> <name> args...

       The event name may be 'begin-foo' or 'end-foo' to indicate an event
       which executes over a span of time, or simply 'foo' to mark a single
       point.
       """
    lineOriented = True

    def __init__(self, completed):
        self.epoch = None
        self.nameEndpoints = {}
        self.nextEp = 1
        self.lineNumber = 0
        self.completed = completed

    def flush(self):
        pass

    def parse(self, line):
        self.lineNumber += 1
        tokens = line.split()
        try:

            # Extract the time, convert to seconds
            nanotime = int(tokens[0])
            if not self.epoch:
                self.epoch = nanotime
            timestamp = (nanotime - self.epoch) / 1000000000.0

            # Detect the start- or end- prefix
            name = tokens[1]
            if name.startswith("begin-"):
                name = name.split('-', 1)[1]
                dirs = ('Down',)
            elif name.startswith("end-"):
                name = name.split('-', 1)[1]
                dirs = ('Up',)
            else:
                dirs = ('Down', 'Up')

            # Generate an 'endpoint' for the event name
            try:
                endpoint = self.nameEndpoints[name]
            except KeyError:
                endpoint = self.nextEp
                self.nameEndpoints[name] = endpoint
                self.nextEp = endpoint + 1

            for dir in dirs:
                trans = Types.Transaction()
                trans.dir = dir
                trans.timestamp = timestamp
                trans.lineNumber = self.lineNumber
                trans.endpt = endpoint
                trans.dev = 0
                trans.status = 0
                trans.datalen = 0x1000
                trans.appendDecoded(" ".join(tokens[1:]))
                self.completed.put(trans)
        except:
            print "Error on line %d:" % self.lineNumber
            traceback.print_exc()


class VmxLogParser(UsbIOParser):
    """Read the VMX log, looking for new USBIO lines and parsing them.
    """
    frame = None
    epoch = None
    lineNumber = 0

    def parse(self, line):
        self.lineNumber += 1

        # Local to the UHCI core
        l = line.split("UHCI:")
        if len(l) == 2:
            m = re.search("- frame ([0-9]+) -", l[1])
            if m:
                self.frame = int(m.group(1))
                # Don't let SOF markers start the clock
                if self.epoch is not None:
                    self.completed.put(Types.SOFMarker(self.parseRelativeTime(line),
                                                       self.frame, self.lineNumber))
                return

        # Local to the EHCI core
        l = line.split("EHCI:")
        if len(l) == 2:
            m = re.search("Execute frame ([0-9]+)[\. ]", l[1])
            if m:
                self.frame = int(m.group(1))
                # Don't let SOF markers start the clock
                if self.epoch is not None:
                    self.completed.put(Types.SOFMarker(self.parseRelativeTime(line),
                                                       self.frame, self.lineNumber))
                return

        # Generic analyzer URBs
        l = line.split("USBIO:")
        if len(l) == 2:
            UsbIOParser.parse(self, l[1][:-1], self.parseRelativeTime(line),
                              self.frame, self.lineNumber)
        else:
            self.flush()

    def parseRelativeTime(self, line):
        """Start the clock when we see our first USB log line"""
        t = self.parseTime(line)
        if self.epoch is None:
            self.epoch = t
        return t - self.epoch

    _timeCache = (None, None)

    def parseTime(self, line):
        """Return a unix-style timestamp for the given line.
           XXX: This assumes the current year, so logs that straddle
                years will have a giant discontinuity in timestamps.
           """
        # Cache the results of strptime. It only changes every
        # second, and this was taking more than 50% of our parsing time!
        stamp = line[:15]
        savedStamp, parsed = self._timeCache
        if savedStamp != stamp:
            parsed = time.strptime(stamp, "%b %d %H:%M:%S")
            self._timeCache = stamp, parsed

        now = time.localtime()
        try:
            usec = int(line[16:19])
        except ValueError:
            usec = 0
        return usec / 1000.0 + time.mktime((
            now.tm_year, parsed.tm_mon, parsed.tm_mday,
            parsed.tm_hour, parsed.tm_min, parsed.tm_sec,
            parsed.tm_wday, parsed.tm_yday, parsed.tm_isdst))


def parseInt(attrs, name, default=None):
    """The Ellisys logs include commas in their integers"""
    try:
        return int(attrs[name].replace(",", ""))
    except (KeyError, ValueError):
        return default

def parseFloat(attrs, name, default=None):
    """The Ellisys logs include commas and spaces in their floating point numbers"""
    try:
        return float(attrs[name].replace(",", "").replace(" ", ""))
    except (KeyError, ValueError):
        return default


class EllisysXmlHandler(xml.sax.handler.ContentHandler):
    """Handles SAX events from an XML log exported by Ellisys
       Visual USB. The completed USB transactions are pushed into
       the provided completion queue.
       """
    frameNumber = None
    device = None
    endpoint = None
    current = None
    characterHandler = None

    def __init__(self, completed):
        self.pipes = {}
        self.pending = {}
        self.completed = completed
        self._frameAttrs = {}

    def startElement(self, name, attrs):
        # This will always call self.startElement_%s where %s is the
        # element name, but the profiler showed us spending quite a lot
        # of time just figuring out who to call, even if this was cached
        # in a dictionary. The tests below are ordered to keep very
        # frequent elements running fast.

        if name == "StartOfFrame":
            # Just stow the SOF attributes, decode them if we end up
            # actually needing them later.
            self._frameAttrs = attrs

        elif name == "data":
            self.characterHandler = self.current.appendHexData

        elif name == "Packet":
            self.startElement_Packet(attrs)

        elif name == "Transaction":
            self.startElement_Transaction(attrs)

        elif name == "Reset":
            self.startElement_Reset(attrs)

    def endElement(self, name):
        self.characterHandler = None
        if name == 'Document':
            for pipe in self.pipes.keys():
                self.completeUrb(pipe, 'End of Log')

    def startElement_Transaction(self, attrs):
        self.device = parseInt(attrs, 'device', 0)
        self.endpoint = parseInt(attrs, 'endpoint')

    def startElement_Reset(self, attrs):
        # Error out any transactions that are active during a reset
        for pipe in self.pipes.keys():
            self.completeUrb(pipe, 'Bus Reset')

    def beginUrb(self, pipe):
        """Simulate a new URB being created on the supplied pipe. This
           begins a Down transaction and makes it pending and current.
           """
        t = Types.Transaction()
        t.dir = 'Down'
        t.dev, t.endpt = pipe
        t.timestamp = self.timestamp
        t.frame = parseInt(self._frameAttrs, 'frameNumber')

        t.status = 0

        self.pipes[pipe] = t
        self.pending[pipe] = t
        self.current = t

    def flipUrb(self, pipe):
        """Begin the Up phase on a particular pipe. This
           completes the Down transaction, and makes an Up
           current (but not pending)
           """
        del self.pending[pipe]
        down = self.pipes[pipe]
        self.completed.put(down)

        up = Types.Transaction()
        up.dir = 'Up'
        up.dev, up.endpt = pipe

        # Up and Down transactions share setup data, if applicable
        if down.hasSetupData():
            up.data = down.data[:8]

        self.pipes[pipe] = up
        self.current = up

    def completeUrb(self, pipe, id):
        """Complete the Up phase on a pipe"""
        if pipe in self.pending:
            self.flipUrb(pipe)
        assert pipe in self.pipes

        t = self.pipes[pipe]
        del self.pipes[pipe]
        self.current = None

        t.timestamp = self.timestamp
        t.frame = parseInt(self._frameAttrs, 'frameNumber')

        if id in ('ACK', 'NYET'):
            t.status = 0
        else:
            t.status = id
        self.completed.put(t)

    def startElement_Packet(self, attrs):
        id = attrs['id']

        # Fast exit for common packets we don't care about
        if id in ('SOF', 'DATA0', 'DATA1'):
            return

        self.timestamp = parseFloat(attrs, 'time')
        if self.endpoint is None:
            return

        if self.endpoint == 0:
            # EP0 is a special case for us, since its transactions
            # consiste of several phases. We always begin with SETUP.
            # If the request has an input stage, we'll see an OUT after
            # that as a handshake. If not, the handshake is an empty
            # IN stage.

            pipe = self.device, 0

            if id == 'SETUP':
                self.beginUrb(pipe)
                self.ep0FinalStage = False

            elif id == 'IN':
                if pipe in self.pending:
                    self.flipUrb(pipe)
                else:
                    self.current = self.pipes[pipe]
                if self.current.data and (ord(self.current.data[0]) & 0x80) == 0:
                    # This is an output request, IN is our last stage
                    self.ep0FinalStage = True

            elif id == 'OUT':
                self.current = self.pipes[pipe]
                if self.current.data and (ord(self.current.data[0]) & 0x80):
                    # This is an input request, OUT is our last stage
                    self.ep0FinalStage = True

            elif id == 'PING':
                # An acknowledged PING packet should never end a control transfer
                self.ep0FinalStage = False

            elif pipe in self.pipes and (
                id == 'STALL' or (id == 'ACK' and self.ep0FinalStage)):
                self.completeUrb(pipe, id)

        else:
            # It's really annoying that the Ellisys logs strip the
            # direction bit from the endpoint number. We have to recover
            # this ourselves.
            if id == 'IN':
                self.endpoint = self.endpoint | 0x80
            pipe = self.device, self.endpoint

            if id in ('OUT', 'IN', 'PING'):
                # These packets indicate that we'd like to be transmitting
                # data to a particular endpoint- so the operating system must
                # now have an active URB.
                if pipe in self.pipes:
                    # Finish a previous packet that wasn't acknowledged.
                    # This will be frequent if isochronous transfers are involved!
                    self.completeUrb(pipe, 'No Handshake')

                self.beginUrb(pipe)

            if pipe in self.pending and id in ('NAK', 'NYET', 'STALL', 'IN'):
                self.flipUrb(pipe)

            if pipe in self.pipes:
                if id == 'ACK':
                    # This accounts for combining individual low-level USB packets
                    # into the larger packets that should be associated with a URB.
                    # We only end a URB when a short packet is transferred.
                    #
                    # FIXME: Determine the real max packet size, rather than
                    #        using this hardcoded nonsense.
                    if len(self.current.data) & 0x3F:
                        self.completeUrb(pipe, id)

                elif id in ('NYET', 'STALL'):
                    # Always complete on an error condition
                    self.completeUrb(pipe, id)

    def characters(self, content):
        # This extra level of indirection seems to be necessary, I guess Expat is
        # binding our functions once at initialization.
        if self.characterHandler:
            self.characterHandler(content)

Types.psycoBind(EllisysXmlHandler)


class EllisysXmlParser:
    """Parses XML files exported from Ellisys Visual USB. This
       is just a glue object that sets up an XML parser and
       sends SAX events to the EllisysXmlHandler.
       """
    lineOriented = False

    def __init__(self, completed):
        self.completed = completed
        self.xmlParser = xml.sax.make_parser()
        self.xmlParser.setContentHandler(EllisysXmlHandler(completed))

    def parse(self, line):
        self.xmlParser.feed(line)


class Follower(threading.Thread):
    """A thread that continuously scans a file, parsing each line"""
    pollInterval = 0.1
    running = True
    progress = 0.0
    progressInterval = 0.2
    progressExpiration = 0

    def __init__(self, filename, parser, progressQueue=None, tailMode=False):
        self.filename = filename
        self.parser = parser
        self.progressQueue = progressQueue

        if os.path.splitext(filename)[1] == ".gz":
            # On a gzip file, we need to read the uncompressed filesize from the footer
            f = open(filename, "rb")
            f.seek(-4, 2)
            self.fileSize = struct.unpack("<l", f.read(4))[0]
            f.seek(0)
            self.file = gzip.GzipFile(fileobj=f)
        else:
            self.file = open(filename)
            self.fileSize = os.fstat(self.file.fileno()).st_size

        if tailMode:
            # Start at the end
            self.file.seek(0, 2)

        threading.Thread.__init__(self)
        atexit.register(self.stop)
        self.progressCallbacks = []

    def run(self):
        try:
            while self.running:
                if self.parser.lineOriented:
                    line = self.file.readline()
                else:
                    line = self.file.read(16384)
                if line:
                    self.parser.parse(line)

                    # Compute our progress only every progressInterval seconds
                    now = time.clock()
                    if now >= self.progressExpiration:
                        self.setProgress(min(1.0, self.file.tell() / self.fileSize))
                        self.progressExpiration = now + self.progressInterval
                else:
                    self.setProgress(1.0)
                    time.sleep(self.pollInterval)
        except KeyboardInterrupt:
            gtk.main_quit()

    def setProgress(self, progress):
        self.progress = progress
        if self.progressQueue:
            self.progressQueue.put(("Loading %s" % os.path.basename(self.filename),
                                    self.progress))

    def stop(self):
        # Keep the queue empty so it doesn't deadlock on put()
        if not self.running:
            return
        self.running = False
        try:
            while 1:
                self.parser.completed.get(False)
        except Queue.Empty:
            pass
        self.join()


class QueueSink:
    """Polls a Queue for new items, via the Glib main loop.
       When they're available, calls a callback with them.
       """
    interval = 200
    timeSlice = 0.25
    maxsize = 512
    batch = range(10)

    def __init__(self, callback):
        self.queue = Queue.Queue(self.maxsize)
        self.callback = callback
        self.poll()

    def poll(self):
        try:
            deadline = time.clock() + self.timeSlice
            while time.clock() < deadline:
                # This avoids calling time.clock() once per queue item.
                for _ in self.batch:
                    try:
                        i = self.queue.get(False)
                    except Queue.Empty:
                        # We have nothing to do, set a longer interval
                        gobject.timeout_add(self.interval, self.poll)
                        return False
                    else:
                        self.callback(i)

        except KeyboardInterrupt:
            gtk.main_quit()

        # Come back after GTK's event queue is idle
        gobject.idle_add(self.poll)
        return False


def chooseParser(filename):
    """Return an appropriate log parser class for the provided filename.
       This implementation does not try to inspect the file's content,
       it just looks at the filename's extension.
       """
    base, ext = os.path.splitext(filename)

    if ext == ".gz":
        return chooseParser(base)
    if ext == ".xml":
        return EllisysXmlParser
    if ext == ".tslog":
        return TimestampLogParser
    return VmxLogParser
