#
# VUsbTools.Decoders.WirelessUsb
# Christopher Friedt <chrisfriedt@gmail.com>
#
# A decoder module for Certified Wireless USB
#
# Copyright (C) 2005-2010 Christopher Friedt. Licensed under the MIT
# License, please see the README.txt. All rights reserved.
#

#################### NOTE: THIS IS A WORK-IN-PROGRESS ####################

from VUsbTools import Decode, Struct
import struct
import sys

####################### PACKED BINARY TYPES   ####################

class UInt8Exp2(Struct.UInt8):
    def decode(self,buffer):
        self._value = 2**buffer[0]
        return buffer[1:]

class ByteArray(Struct.UInt8):
    def __init__(self,l,name):
        if l <= 0:
            raise ValueError('arrays must be greater than or equal to zero')
        x = 'B' * l
        y = '%02X ' * (l-1) + '%02X'
        self._length = l
        self._name = name
        self._format = x
        self._strFormat = y
        self._value = None
    def decode(self,buffer):
        self._value = struct.unpack(self._format,buffer[:self._length])
        return buffer[self._length:]

# FIXME: this is an ugly hack
class KeyDescriptor(Struct.Item):
    def __init__(self,l,name):
        if l < 6:
            raise ValueError('key descriptors must be >= 6 bytes')
        self._name = name
        self._value = None
        self._format = 'BBBBBB' + (l-6) * 'B'
        self._length = l

    def decode(self,buffer):
        tTKID = struct.unpack('BBB',buffer[2:5])
        self._value  = "\n    tTKID = %02x %02x %02x\n" % (tTKID[0],tTKID[1],tTKID[2])
        if self._length > 0:
            l = self._length - 6
            self._value += "    keyData = "
            for i in range(l-1):
                self._value += "%02x " % ord(buffer[6+i])
            self._value += "%02x" % ord(buffer[l-1])

        return buffer[self._length:]

# FIXME: this is an ugly hack
class RPipeDescriptor(Struct.Item):
    def __init__(self,name):
        self._name = name
        self._value = None
        self._format = 28 * 'B'

    def decode(self,buffer):
        if len(buffer) < 28:
            raise ValueError('rpipe descriptor requires 24 bytes')

        wRPipeIndex = struct.unpack('<H',buffer[2:4])
        wRequests = struct.unpack('<H',buffer[4:6])
        wBlocks = struct.unpack('<H',buffer[6:8])
        wMaxPacketSize = struct.unpack('<H',buffer[8:10])
        bHSHubPort = ord(buffer[11])
        bSpeed = ord(buffer[12])
        bDeviceAddress = ord(buffer[13])
        bEndpointAddress = ord(buffer[14])
        bDataSequence = ord(buffer[15])
        dwCurrentWindow = struct.unpack('<I',buffer[16:20])
        bMaxDataSequence = ord(buffer[20])
        bInterval = ord(buffer[21])
        bOverTheAirInterval = ord(buffer[22])
        bmAttribute = ord(buffer[23])
        bmCharacteristics = ord(buffer[24])
        bmRetryOptions = ord(buffer[25])
        wNumTransactionErrors = struct.unpack('<H',buffer[26:28])

        self._value  = "\n"
        self._value += "    wRPipeIndex = %d\n" % wRPipeIndex
        self._value += "    wRequests = %d\n" % wRequests
        self._value += "    wBlocks = %d\n" % wBlocks
        self._value += "    wMaxPacketSize = %d\n" % wMaxPacketSize
        self._value += "    bHSHubPort = %d\n" % bHSHubPort
        self._value += "    bSpeed = %d\n" % bSpeed
        self._value += "    bDeviceAddress = %d\n" % bDeviceAddress
        self._value += "    bEndpointAddress = %d\n" % bEndpointAddress
        self._value += "    bDataSequence = %d\n" % bDataSequence
        self._value += "    dwCurrentWindow = %d\n" % dwCurrentWindow
        self._value += "    bMaxDataSequence = %d\n" % bMaxDataSequence
        self._value += "    bInterval = %d\n" % bInterval
        self._value += "    bOverTheAirInterval = %d\n" % bOverTheAirInterval
        self._value += "    bmAttribute = 0x%02x\n" % bmAttribute
        self._value += "    bmCharacteristics = 0x%02x\n" % bmCharacteristics
        self._value += "    bmRetryOptions = 0x%02x\n" % bmRetryOptions
        self._value += "    wNumTransactionErrors = %d" % wNumTransactionErrors

        return buffer[28:]

####################### UWB RADIO ########################

# Command Results
rcResultCodes = Struct.EnumDict({
    0x00: 'SUCCESS',
    0x01: 'FAILURE',
    0x02: 'FAILURE_HARDWARE',
    0x03: 'FAILURE_NO_SLOTS',
    0x04: 'FAILURE_BEACON_TOO_LARGE',
    0x05: 'FAILURE_INVALID_PARAMETER',
    0x06: 'FAILURE_UNSUPPORTED_PWR_LEVEL',
    0x07: 'TIME_OUT',
    })

rcCommandOrEventTypes = Struct.EnumDict({
    0x00: 'GENERAL',
    # the rest are vendor / reserved
    })

rcCommandsOrEvents = Struct.EnumDict({
    # NOTIFICATIONS
    0x00: 'AS_PROBE_IE_RECEIVED',
    0x01: 'BEACON_RECEIVED',
    0x02: 'BEACON_SIZE_CHANGE',
    0x03: 'BPOIE_CHANGE',
    0x04: 'BP_SLOT_CHANGE',
    0x05: 'BP_SWITCH_IE_RECEIVED',
    0x06: 'DEV_ADDR_CONFLICT',
    0x07: 'DRP_AVAILABILITY_CHANGE',
    0x08: 'DRP',
    # 0x09-0x0f reserved

    # COMMANDS
    0x10: 'CHANNEL_CHANGE',
    0x11: 'DEV_ADDR',
    0x12: 'GET_IE',
    0x13: 'RESET',
    0x14: 'SCAN',
    0x15: 'SET_BEACON_FILTER',
    0x16: 'SET_DRP_IE',
    0x17: 'SET_IE',
    0x18: 'SET_NOTIFICATION_FILTER',
    0x19: 'SET_TX_POWER',
    0x1a: 'SLEEP',
    0x1b: 'START_BEACONING',
    0x1c: 'STOP_BEACONING',
# XXX: This is not part of the WUSB spec, but exists with Wisair hardware
    0xfffe: 'HEARTBEAT',
    })

class UwbControlDescriptorGroup(Struct.Group):

    requests = Struct.EnumDict({
        (0x21,0x28):"exec_rc_cmd"
    })

    headerStruct = lambda self: (
        Struct.UInt8("bCommandType"),
        Struct.UInt16("wCommand"),
        Struct.UInt8("bCommandContext"),
        )

    struct_channel_change = lambda self: (
        Struct.UInt8("bChannelChangeCountdown"),
        Struct.UInt8("bNewChannelNumber"),
        )

    struct_dev_addr = lambda self: (
        Struct.UInt8Hex("bmOperationType"),
# XXX: WUSB Spec says this is a 64-bit address, but they are only 48-bit
        ByteArray(6,"baAddr"),
        )

    struct_get_ie = lambda self: (
        )

    struct_reset = lambda self: (
        )

    struct_scan = lambda self: (
        Struct.UInt8("bChannelNumber"),
        Struct.UInt8("bScanState"),
        )

    struct_set_beacon_filter = lambda self: (
        ByteArray(6,"bmBeaconSlots"),
        Struct.UInt8("bEnableState"),
        )

    struct_set_drp_ie = lambda self, n: (
# XXX: WUSB Spec says that a bExplicit field exists here
        Struct.UInt16("wIELength"),
        ByteArray(n,"IEData"),
        )

    struct_set_ie = lambda self, n: (
        Struct.UInt16("wIELength"),
        ByteArray(n,"IEData"),
        )

    struct_set_notification_filter = lambda self: (
        Struct.UInt16("wNotification"),
        Struct.UInt8("bEnableState"),
        )

    struct_set_tx_power = lambda self: (
        Struct.UInt8("bPowerLevel"),
        )

    struct_sleep = lambda self: (
        Struct.UInt8("bHibernationCount"),
        Struct.UInt8("bHibernateDuration"),
        )

    struct_start_beaconing = lambda self: (
        Struct.UInt16("wBPSTOffset"),
        Struct.UInt8("bChannelNumber"),
        )

    struct_stop_beaconing = lambda self: (
        )

    def __init__(self):
        Struct.Group.__init__(self, "descriptors")

    def decode(self, buffer):

        hdr_sz = 4

        dnames = { "channel_change":"Channel Change", "dev_addr":"Dev Addr",
                   "get_ie":"Get IE", "reset":"Reset", "scan":"Scan",
                   "set_beacon_filter":"Set Beacon Filter", "set_drp_ie":"Set DRP IE",
                   "set_ie":"Set IE", "set_notification_filter":"Set Notification Filter",
                   "set_tx_power":"Set TX Power", "sleep":"Sleep",
                   "start_beaconing":"Start Beaconing", "stop_beaconing":"Stop Beaconing",
                }

        # rcCommands do not contain a convenient bLength field, so we need to
        # peek into them occasionally
        dlens = { "channel_change":6, "dev_addr":11, "get_ie":4, "reset":4,
                    "scan":6, "set_beacon_filter":11, "set_drp_ie":-1, "set_ie":-1,
                    "set_notification_filter":7, "set_tx_power":5, "sleep":6,
                    "start_beaconing":7, "stop_beaconing":4,
                    }

        # Common descriptor header
        buffer = Struct.Group.decode(self, buffer, self.headerStruct())

        cmdt = rcCommandOrEventTypes[self.bCommandType]
        if cmdt is not 'GENERAL':
            raise ValueError("rcCommandType %s is not supported" % cmdt )

        # Decode command type
        cmd = str(rcCommandsOrEvents[self.wCommand]).lower()
        if str(cmd).startswith('0x'):
            raise ValueError("rcCommand %s is not supported" % cmd )

        self.name = dnames[cmd]

        d = getattr(self, "struct_%s" % cmd, lambda: None)

        up = lambda buf, ofs: struct.unpack_from('<H',buf,ofs)[0]

        dlen = dlens[cmd]
        if dlen == -1:
            if cmd == "set_drp_ie":
# XXX: WUSB Spec says that a bExplicit field exists here
                nb = 6
                n = up(buffer,0)
            elif cmd == "set_ie":
                nb = 6
                n = up(buffer,0)
            dlen = nb + n
            dr = d(n)
        else:
            dr = d()

        descriptor = buffer[:dlen-hdr_sz]
        buffer = buffer[dlen-hdr_sz:]

        Struct.Group.decode(self, descriptor, dr)
        return buffer

class UwbControlDecoder(Decode.ControlDecoder):
    classRequests = Struct.EnumDict({
        0x28: "EXEC_RC_CMD",
        })

    def handleEvent(self, event):
        if not event.isDataTransaction():
            return
        setup = Decode.SetupPacket(event)

        # Look up the request name
        setup.requestName = getattr(self, "%sRequests" % setup.type,
                                    Struct.EnumDict())[setup.request]

        # Look up a corresponding decoder
        d = getattr(self, "decode_%s" % setup.requestName, self.decodeGeneric)
        d(setup)

    def decode_EXEC_RC_CMD(self,setup):
        setup.event.decoded = None
        setup.event.decodedSummary = None
        x = UwbControlDescriptorGroup()
        buffer = setup.event.data[8:]
        setup.event.data = x.decode(buffer)
        setup.event.pushDecoded(str(x))
        setup.event.pushDecoded('UWB Command: %s' % x.name )

class UwbEventDescriptorGroup(Struct.Group):

    headerStruct = lambda self: (
        Struct.UInt8("bEventType"),
        Struct.UInt16("wEvent"),
        Struct.UInt8("bEventContext"),
        )

    ###########################
    # Command Status / Result #
    ###########################

    resultStruct = lambda self: (
        Struct.UInt8("bResultCode"),
        )
    struct_channel_change = resultStruct
    struct_dev_addr = lambda self:(
# XXX: WUSB Spec says this is a 64-bit address, but they are only 48-bit
        ByteArray(6,"baAddr"),
        Struct.UInt8("bResultCode"),
        )
    struct_get_ie = lambda self, n:(
        Struct.UInt16("wIELength"),
        ByteArray(n,"IEData"),
        )
    struct_reset = resultStruct
    struct_scan = resultStruct
    struct_set_beacon_filter = resultStruct
    struct_set_drp_ie = lambda self:(
        Struct.UInt16("wRemainingSpace"),
        Struct.UInt8("bResultCode"),
        )
    struct_set_ie = struct_set_drp_ie
    struct_set_notification_filter = resultStruct
    struct_set_tx_power = resultStruct
    struct_sleep = resultStruct
    struct_start_beaconing = resultStruct
    struct_stop_beaconing = resultStruct

    #################
    # Notifications #
    #################

    struct_as_probe_ie_received = lambda self, n: (
        Struct.UInt16("wSrcAddr"),
        Struct.UInt16("wIELength"),
        ByteArray(n,"IEData"),
        )
    struct_beacon_received = lambda self, n: (
        Struct.UInt8("bChannelNumber"),
        Struct.UInt8("bBeaconType"),
        Struct.UInt16("wBPSTOffset"),
        Struct.UInt8("bLQI"),
        Struct.UInt8("bRSSI"),
        Struct.UInt16("wBeaconInfoLength"),
        ByteArray(n,"BeaconInfo"),
        )
    struct_beacon_size_change = lambda self: (
        Struct.UInt16("wNewBeaconSize"),
        )
    struct_bpoie_change = lambda self, n: (
        Struct.UInt16("wBPOIELength"),
        ByteArray(n,"BPOIE"),
        )
    struct_beacon_slot_change = lambda self: (
        Struct.UInt8("bSlotNumber"),
        )
    struct_bp_switch_ie_received = struct_as_probe_ie_received
    struct_dev_addr_conflict = lambda self: (
        )

    struct_drp_availability_change = lambda self: (
# XXX: WUSB Spec claims wIELength field. However, IEData is a fixed 32-bytes
        ByteArray(32,"IEData"),
        )
    struct_drp = lambda self, n: (
        Struct.UInt16("wSrcAddr"),
        Struct.UInt8("bExplicit"),
        Struct.UInt16("wIELength"),
        ByteArray(n,"IEData"),
        )
# XXX: This is not part of the WUSB spec, but exists with Wisair hardware
    struct_heartbeat = lambda self: (
        ByteArray(8,"nothing"),
        )

    def __init__(self):
        Struct.Group.__init__(self, "descriptors")

    def decode(self,buffer2):

        buffer = buffer2

        hdr_sz = 4

        dlens = { "channel_change":5,
# XXX: WUSB Spec says this is a 64-bit address, but they are only 48-bit
            "dev_addr":11,
            "get_ie":-1, "reset":5,
            "scan":5, "set_beacon_filter":5, "set_drp_ie":7, "set_ie":7,
            "set_notification_filter":5, "set_tx_power":5, "sleep":5,
            "start_beaconing":5, "stop_beaconing":5, "as_probe_ie_received":-1,
            "beacon_received":-1, "beacon_size_change":6, "bpoie_change":-1,
            "bp_slot_change":5, "bp_switch_ie_received":-1, "dev_addr_conflict":4,
# XXX: WUSB Spec claims wIELength field. However, IEData is a fixed 32-bytes
            "drp_availability_change":36,
# XXX: This is not part of the WUSB spec, but exists with Wisair hardware
            "drp":-1, "heartbeat":12,
            }

        dnames = { "channel_change":"Channel Change", "dev_addr":"Dev Addr",
                   "get_ie":"Get IE", "reset":"Reset", "scan":"Scan",
                   "set_beacon_filter":"Set Beacon Filter", "set_drp_ie":"Set DRP IE",
                   "set_ie":"Set IE", "set_notification_filter":"Set Notification Filter",
                   "set_tx_power":"Set TX Power", "sleep":"Sleep",
                   "start_beaconing":"Start Beaconing", "stop_beaconing":"Stop Beaconing",
                   "as_probe_ie_received":"AS Probe IE Received", "beacon_received":"Beacon Received",
                   "beacon_size_change":"Beacon Size Change", "bpoie_change":"BPOIE Change",
                   "bp_slot_change":"BP Slot Change", "bp_switch_ie_received":"BP Switch IE Received",
                   "dev_addr_conflict":"Dev Addr Conflict", "drp_availability_change":"DRP Availability Change",
                   "drp":"DRP",
# XXX: This is not part of the WUSB spec, but exists with Wisair hardware
                   "heartbeat":"HeartBeat" }

        if not buffer:
            print 'WirelessUSB Radio Event: buffer is empty'
            return

        # Common descriptor header
        buffer = Struct.Group.decode(self, buffer, self.headerStruct())

        evt = rcCommandOrEventTypes[self.bEventType]
        if evt is not 'GENERAL':
            raise ValueError("rcEventType %s is not supported" % evt )

        # Decode command type
        ev = rcCommandsOrEvents[self.wEvent].lower()
        if ev.startswith('0x'):
            raise ValueError("rcEvent %s is not supported" % ev )

        self.ev_name = dnames[ev]

        d = getattr(self, "struct_%s" % ev, lambda: None)

        up = lambda buf, ofs: struct.unpack_from('<H',buf,ofs)[0]

        dlen = dlens[ev]
        blen = len(buffer)

        if blen < dlen - hdr_sz:
            print 'Buffer Dump (incorrect size for %s)' % self.ev_name
            for i in range(blen):
                print '0x%02x' % ord(buffer[i])
            raise ValueError( "expected packet length >= %d but have %d" %
                              (dlen-hdr_sz,len(buffer)) )
        if dlen == -1:
            if ev == "get_ie":
                nb = 6
                n = up(buffer,0)
            elif ev == "as_probe_ie_received" or ev == "bp_switch_ie_received":
                nb = 8
                n = up(buffer,2)
            elif ev == "beacon_received":
# XXX: WUSB Spec is missing bBeaconType field at offset 5
                nb = 12
                n = up(buffer,6)
            elif ev == "bpoie_change":
                nb = 6
                n = up(buffer,0)
# XXX: WUSB Spec claims wIELength field. However, IEData is a fixed 32-bytes
            elif ev == "drp_availability_change":
                nb = 4
                n = up(buffer,0)
            elif ev == "drp":
                nb = 9
                n = up(buffer,3)
            dlen = nb + n
            dr = d(n)
        else:
            dr = d()

        buffer = Struct.Group.decode(self, buffer, dr)
        return buffer

class UwbEventDecoder():
    descriptorClass = UwbEventDescriptorGroup

    def handleEvent(self,event):
        if not event.data:
            return
        x = self.descriptorClass()
        event.data = x.decode(event.data)
        event.pushDecoded( str(x) )
        label = "Response" if x.wEvent in range(0x10,0x1c + 1) else "Notification"
        event.pushDecoded( "UWB %s: %s" % (label,x.ev_name) )

####################### HOST WIRE ADAPTER     ####################

wusbChannelTimeTypes = Struct.EnumDict({
    0x0000: "TIME_ADJ",
    0x0001: "TIME_BPST",
    0x0002: "TIME_WUSB",
})

class HwaControlDescriptorGroup(Struct.Group):

    doffs = { "add_mmc_ie":2, "get_bpst_adjustment":4, "get_bpst_time":4,
             "get_wusb_time":4, "remove_mmc_ie":4, "set_device_encryption":2,
             "set_device_info":4, "set_device_key":2, "set_group_key":2,
             "set_num_dnts_slots":2, "set_wusb_cluster_id":2, "set_wusb_mas":4,
             "set_wusb_stream_index":2, "wusb_channel_stop":2,
             }

    dlens = { "add_mmc_ie":-1, "get_bpst_adjustment":1, "get_bpst_time":3,
             "get_wusb_time":3, "remove_mmc_ie":0, "set_device_encryption":0,
             "set_device_info":36, "set_device_key":-1, "set_group_key":-1,
             "set_num_dnts_slots":0, "set_wusb_cluster_id":0, "set_wusb_mas":0,
             "set_wusb_stream_index":0, "wusb_channel_stop":0, }

    requests = Struct.EnumDict({
       (0x21,0x14):"add_mmc_ie",
       (0xa1,0x19):"GET_TIME", # requires further differentiation
       (0x21,0x15):"remove_mmc_ie",
       (0x21,0x0d):"set_device_encryption",
       (0x21,0x18):"set_device_info",
       (0x21,0x07):"SET_DESCRIPTOR", # requires further differentiation
       (0x21,0x16):"set_num_dnts_slots",
       (0x21,0x17):"set_wusb_cluster_id",
       (0x21,0x1b):"set_wusb_mas",
       (0x21,0x1a):"set_wusb_stream_index",
       (0x21,0x1c):"wusb_channel_stop",
    })

    struct_add_mmc_ie = lambda self, n: (
        Struct.UInt8("Interval"),
        Struct.UInt8("RepeatCount"),
        Struct.UInt8("IEHandle"),
        Struct.UInt8("InterfaceNumber"),
        Struct.UInt16("IELength"),
        ByteArray(n,"IEBlock"),
    )
    struct_get_bpst_adjustment = lambda self: (
        Struct.UInt16("InterfaceNumber"),
        Struct.UInt16("wLength"),
        Struct.UInt8("AdjustmentValue"),
    )
    struct_get_bpst_time = lambda self: (
        Struct.UInt16("InterfaceNumber"),
        Struct.UInt16("wLength"),
        ByteArray(3,"WUSBChannelTime"),
    )
    struct_get_wusb_time = lambda self: (
        Struct.UInt8("InterfaceNumber"),
        Struct.UInt16("wLength"),
        ByteArray(3,"WUSBChannelTime"),
    )
    struct_remove_mmc_ie = lambda self: (
        Struct.UInt8("IEHandle"),
        Struct.UInt16("InterfaceNumber"),
    )
    struct_set_device_encryption = lambda self: (
        Struct.UInt8("EncryptionValue"),
        Struct.UInt8("DeviceIndex"),
        Struct.UInt8("InterfaceNumber"),
    )
    struct_set_device_info = lambda self: (
        Struct.UInt8("DeviceIndex"),
        Struct.UInt8("InterfaceNumber"),
        Struct.UInt16("wLength"),
        ByteArray(36,"DeviceInformationBuffer"),
    )
    struct_set_device_key = lambda self, n: (
        Struct.UInt8("DescriptorType"),
        Struct.UInt8("KeyIndex"),
        Struct.UInt8("DeviceIndex"),
        Struct.UInt8("InterfaceNumber"),
        Struct.UInt16("KeyDescriptorLength"),
        KeyDescriptor(n,"KeyDescriptor"),
    )
    struct_set_group_key = lambda self, n: (
        Struct.UInt8("DescriptorType"),
        Struct.UInt8("KeyIndex"),
        Struct.UInt16("InterfaceNumber"),
        Struct.UInt16("KeyDescriptorLength"),
        KeyDescriptor(n,"KeyDescriptor"),
    )
    struct_set_num_dnts_slots = lambda self: (
        Struct.UInt8("Interval"),
        Struct.UInt8("NumberOfDNTSSlots"),
        Struct.UInt16("InterfaceNumber"),
    )
    struct_set_wusb_cluster_id = lambda self: (
        Struct.UInt8Hex("Cluster ID"),
        Struct.UInt16("InterfaceNumber"),
    )
    struct_set_wusb_mas = lambda self: (
        Struct.UInt16("InterfaceNumber"),
        Struct.UInt16("wLength"),
        ByteArray(32,"WUSBMAS"),
    )
    struct_set_wusb_stream_index = lambda self: (
        Struct.UInt16("StreamIndex"),
        Struct.UInt16("InterfaceNumber"),
    )
    struct_wusb_channel_stop = lambda self: (
        Struct.UInt16("WUSBChannelTimeOffset"),
        Struct.UInt16("InterfaceNumber"),
    )

    def __init__(self):
        Struct.Group.__init__(self,"descriptors")

    def decode(self,event):

        # erase the default decoding
        event.decoded = None
        event.decodedSummary = None

        setup = Decode.SetupPacket(event)
        self.setup = setup
        request = self.requests.get((setup.bitmap,setup.request))
        assert(request)

        # perfrorm any other differentiation necessary
        if request == "GET_TIME":
            type = wusbChannelTimeTypes[setup.wValue]
            if type == "TIME_ADJ":
                request = "get_bpst_adjustment"
            elif type == "TIME_BPST":
                request = "get_bpst_time"
            elif type == "TIME_WUSB":
                request = "get_wusb_time"
        elif request == "SET_DESCRIPTOR":
            if not setup.wIndexHigh:
                request = "set_group_key"
            else:
                request = "set_device_key"

        self.request = request

        # process data, if it exists
        d = getattr(self, "struct_%s" % request, None)
        if self.dlens[request] == -1:
            n = setup.wLength
            dr = d(n)
        else:
            dr = d()

        offs = self.doffs.get(request)
        Struct.Group.decode(self, event.data[offs:], dr)

class HwaControlDecoder(Decode.ControlDecoder):

    dnames = {
        "add_mmc_ie":"Add MMC IE", "get_bpst_adjustment":"Get BPST Adjustment",
        "get_bpst_time":"Get BPST Time", "get_wusb_time":"Get WUSB Time",
        "remove_mmc_ie":"Remove MMC IE",
        "set_device_encryption":"Set Device Encryption",
        "set_device_info":"Set Device Info", "set_device_key":"Set Device Key",
        "set_group_key":"Set Group Key",
        "set_num_dnts_slots":"Set Num DNTS Slots",
        "set_wusb_cluster_id":"Set WUSB Cluster ID",
        "set_wusb_mas":"Set WUSB MAS",
        "set_wusb_stream_index":"Set WUSB Stream Index",
        "wusb_channel_stop":"WUSB Channel Stop",
    }

    def handleEvent(self,event):
        cmd = HwaControlDescriptorGroup()
        cmd.decode(event)
        event.pushDecoded( "%s" % cmd )
        event.pushDecoded("HWA Command (%s)" % self.dnames.get(cmd.request) )

class HwaEventDecoder():

    def handleEvent(self,event):
        buffer = event.data
        if buffer:
            print 'HwaEvent Dump:'
            for i in range(len(buffer)):
                print '0x%02x' % ord(buffer[i])
# TODO: finish this off
        z = 0 + 0

####################### DEVICE WIRE ADAPTER   ####################

class DwaControlDescriptorGroup(Struct.Group):

    doffs = { "clear_port_feature":2, "get_port_status":4,
              "set_isoep_attributes":4, "set_port_feature":2,
             }

    dlens = { "clear_port_feature":8, "get_port_status":12,
              "set_isoep_attributes":14, "set_port_feature":8, }

    requests = Struct.EnumDict({
       (0x24,0x01):"clear_port_feature",
       (0xa4,0x00):"get_port_status",
       (0x22,0x1e):"set_isoep_attributes",
       (0x24,0x03):"set_port_feature",
    })

    struct_clear_port_feature = lambda self: (
        Struct.UInt16("FeatureSelector"),
        Struct.UInt8("Selector"),
        Struct.UInt8("PortIndex"),
    )
    struct_get_port_status = lambda self: (
        Struct.UInt16("PortIndex"),
        Struct.UInt16("wLength"),
        ByteArray(4,"PortStatusAndChangeStatus"),
    )
    struct_set_isoep_attributes = lambda self: (
        Struct.UInt16("EndpointAddress"),
        Struct.UInt16("wLength"),
        ByteArray(3,"EndpointAttributes"),
    )
    struct_set_port_feature = lambda self: (
        Struct.UInt16("FeatureSelector"),
        Struct.UInt8("Selector"),
        Struct.UInt8("PortIndex"),
    )

    def __init__(self):
        Struct.Group.__init__(self,"descriptors")

    def decode(self,event):

        # erase the default decoding
        event.decoded = None
        event.decodedSummary = None

        setup = Decode.SetupPacket(event)
        self.setup = setup
        request = self.requests.get((setup.bitmap,setup.request))
        assert(request)

        self.request = request

        # process data, if it exists
        d = getattr(self, "struct_%s" % request, None)
        dr = d()

        offs = self.doffs.get(request)
        Struct.Group.decode(self, event.data[offs:], dr)

class DwaControlDecoder(Decode.ControlDecoder):

    dnames = { "clear_port_feature":"Clear Port Feature",
              "get_port_status":"Get Port Status",
              "set_isoep_attributes":"Set ISOEP Attributes",
              "set_port_feature":"Set Port Feature", }

    def handleEvent(self,event):
        cmd = DwaControlDescriptorGroup()
        cmd.decode(event)
        event.pushDecoded( "%s" % cmd )
        event.pushDecoded("DWA Command (%s)" % self.dnames.get(cmd.request) )

class DwaEventDecoder():
    def handleEvent(self,event):
# TODO: finish this off
        z = 0 + 0

####################### WIRE ADAPTER (COMMON) ####################

class WaControlDescriptorGroup(Struct.Group):

    doffs = { "abort_rpipe":4, "clear_rpipe_feature":2,
              "clear_wire_adapter_feature":2, "get_rpipe_descriptor":2,
              "get_rpipe_status":4, "get_wire_adapter_status":4,
              "set_rpipe_descriptor":2, "set_rpipe_feature":2,
              "set_wire_adapter_feature":2, "reset_rpipe":4, }

    dlens = { "abort_rpipe":8, "clear_rpipe_feature":8,
              "clear_wire_adapter_feature":8, "get_rpipe_descriptor":36,
              "get_rpipe_status":9, "get_wire_adapter_status":12,
              "set_rpipe_descriptor":36, "set_rpipe_feature":8,
              "set_wire_adapter_feature":8, "reset_rpipe":8, }

    requests = Struct.EnumDict({
        (0x25,0x0e): "abort_rpipe",
        (0x25,0x01): "clear_rpipe_feature",
        (0x21,0x01): "clear_wire_adapter_feature",
        (0xa5,0x06): "get_rpipe_descriptor",
        (0xa5,0x00): "get_rpipe_status",
        (0xa1,0x00): "get_wire_adapter_status",
        (0x25,0x07): "set_rpipe_descriptor",
        (0x25,0x03): "set_rpipe_feature",
        (0x21,0x03): "set_wire_adapter_feature",
        (0x25,0x0f): "reset_rpipe",
    })

    struct_abort_rpipe = lambda self: (
        Struct.UInt16("RPipeIndex"),
    )
    struct_clear_rpipe_feature = lambda self: (
        Struct.UInt16("FeatureSelector"),
        Struct.UInt16("RPipeIndex"),
    )
    struct_clear_wire_adapter_feature = lambda self: (
        Struct.UInt16("FeatureSelector"),
        Struct.UInt16("InterfaceNumber"),
    )
    struct_get_rpipe_descriptor = lambda self: (
        Struct.UInt16("DescriptorType"),
        Struct.UInt16("RPipeIndex"),
        Struct.UInt16("DescriptorLength"),
        RPipeDescriptor("RPipeDescriptor"),
    )
    struct_get_rpipe_status = lambda self: (
        Struct.UInt16("RPipeIndex"),
        Struct.UInt16("wLength"),
        Struct.UInt8("RPipeStatus"),
    )
    struct_get_wire_adapter_status = lambda self: (
        Struct.UInt16("InterfaceNumber"),
        Struct.UInt16("wLength"),
        ByteArray(4,"WireAdapterStatus"),
    )
    struct_set_rpipe_descriptor = lambda self: (
        Struct.UInt16("DescriptorType"),
        Struct.UInt16("RPipeIndex"),
        Struct.UInt16("DescriptorLength"),
        RPipeDescriptor("RPipeDescriptor"),
    )
    struct_set_rpipe_feature = struct_clear_rpipe_feature
    struct_set_wire_adapter_feature = struct_clear_wire_adapter_feature
    struct_reset_rpipe = struct_abort_rpipe

    def __init__(self):
        Struct.Group.__init__(self,"descriptors")

    def decode(self,event):

        # erase the default decoding
        event.decoded = None
        event.decodedSummary = None

        setup = Decode.SetupPacket(event)
        self.setup = setup
        request = self.requests.get((setup.bitmap,setup.request))
        assert(request)

        self.request = request

        # process data, if it exists
        d = getattr(self, "struct_%s" % request, None)
        dr = d()

        offs = self.doffs.get(request)
        Struct.Group.decode(self, event.data[offs:], dr)

class WaControlDecoder(Decode.ControlDecoder):
    dnames = { "abort_rpipe":"Abort RPipe",
              "clear_rpipe_feature":"Clear RPipe Feature",
              "clear_wire_adapter_feature":"Clear Wire Adapter Feature",
              "get_rpipe_descriptor":"Get RPipe Descriptor",
              "get_rpipe_status":"Get RPipe Status",
              "get_wire_adapter_status":"Get Wire Adapter Status",
              "set_rpipe_descriptor":"Set RPipe Descriptor",
              "set_rpipe_feature":"Set RPipe Feature",
              "set_wire_adapter_feature":"Set Wire Adapter Feature",
              "reset_rpipe":"Reset RPipe",    }

    def handleEvent(self,event):
        cmd = WaControlDescriptorGroup()
        cmd.decode(event)
        event.pushDecoded( "%s" % cmd )
        event.pushDecoded("WA Command (%s)" % self.dnames.get(cmd.request) )

class WaEventDecoder():
    def handleEvent(self,event):
# TODO: finish this off
        z = 0 + 0

####################### SECURITY           #######################

class SecurityControlDescriptorGroup(Struct.Group):

    doffs = { "get_key":2, "set_key":2, "handshake1":6, "handshake2":6,
              "handshake3":6, "get_security_descriptor":2, "set_encryption":2,
              "get_encryption":8, "set_connection_context":8,
              "set_security_data":2, "get_security_data":2, }

    dlens = { "get_key":-1, "set_key":-1, "handshake1":-1, "handshake2":-1,
              "handshake3":-1, "get_security_descriptor":-1, "set_encryption":8,
              "get_encryption":9, "set_connection_context":56,
              "set_security_data":-1, "get_security_data":-1, }

    requests = Struct.EnumDict({
        (0x80,0x06): "GET_DESCRIPTOR", # requires further differentiation
        (0x00,0x07): "set_key",
        (0x00,0x0f): "SET_HANDSHAKE", # requires further differentiation
        (0x80,0x10): "handshake2",
        (0x00,0x0d): "set_encryption",
        (0x80,0x0e): "get_encryption",
        (0x00,0x11): "set_connection_context",
        (0x00,0x12): "set_security_data",
        (0x80,0x13): "get_security_data",
    })
    struct_get_key = lambda self, n:(
        Struct.UInt8("DescriptorType"),
        Struct.UInt8("KeyIndex"),
        Struct.UInt16("wIndex"),
        Struct.UInt16("DescriptorLength"),
        KeyDescriptor(n,"KeyDescriptor"),
    )
    struct_set_key = struct_get_key
    struct_handshake1 = lambda self, n: (
        Struct.UInt16("DataLength"),
        ByteArray(n,"HandshakeData"),
    )
    struct_handshake2 = struct_handshake1
    struct_handshake3 = struct_handshake1
    struct_get_security_descriptor = lambda self, n: (
        Struct.UInt16("DescriptorType"),
        Struct.UInt16("wIndex"),
        Struct.UInt16("DescriptorLength"),
        ByteArray(n,"DescriptorData"),
    )
    struct_set_encryption = lambda self: (
        Struct.UInt16("Encryptionvalue"),
    )
    struct_get_encryption = lambda self: (
        Struct.UInt8("EncryptionValue"),
    )
    struct_set_connection_context = lambda self, n: (
        ByteArray(n,"ConnectionContext"),
    )
    struct_set_security_data = lambda self, n: (
        Struct.UInt16("DataNumber"),
        Struct.UInt16("wIndex"),
        Struct.UInt16("DataLength"),
        ByteArray(n,"SecurityData"),
    )
    struct_set_rpipe_descriptor = lambda self, n: (
        Struct.UInt16("DataNumber"),
        Struct.UInt16("wIndex"),
        Struct.UInt16("DataLength"),
        ByteArray(n,"SecurityData"),
    )

    def __init__(self):
        Struct.Group.__init__(self,"descriptors")

    def decode(self,event):


        # erase the default decoding
        event.decoded = None
        event.decodedSummary = None

        setup = Decode.SetupPacket(event)
        self.setup = setup
        request = self.requests.get((setup.bitmap,setup.request))
        assert(request)

        # perfrorm any other differentiation necessary
        if request == "GET_DESCRIPTOR":
            if not setup.wValueHigh:
                request = "get_security_descriptor"
            else:
                request = "get_key"
        elif request == "SET_HANDSHAKE":
            if setup.wValue == 1:
                request = "handshake1"
            else:
                request = "handshake3"

        self.request = request

        # process data, if it exists
        d = getattr(self, "struct_%s" % request, None)
        if self.dlens[request] == -1:
            n = setup.wLength
            dr = d(n)
        else:
            dr = d()

        offs = self.doffs.get(request)
        Struct.Group.decode(self, event.data[offs:], dr)

class SecurityControlDecoder(Decode.ControlDecoder):
    dnames = { "get_key":"Get Key",
              "set_key":"Set Key",
              "handshake1":"Handshake 1",
              "handshake2":"Handshake 2",
              "handshake3":"Handshake 3",
              "get_security_descriptor":"Get Security Descriptor",
              "set_encryption":"Set Encryption",
              "get_encryption":"Get Encryption",
              "set_connection_context":"Set Connection Context",
              "set_security_data":"Set Security Data",
              "get_security_data":"Get Security Data", }

    def handleEvent(self,event):
        cmd = SecurityControlDescriptorGroup()
        cmd.decode(event)
        event.pushDecoded( "%s" % cmd )
        event.pushDecoded("Security Command (%s)" % self.dnames.get(cmd.request) )

class SecurityEventDecoder():
    def handleEvent(self,event):
        z = 0 + 0

####################### WIRELESS USB       #######################

class WusbControlDecoder(Decode.ControlDecoder):
    def handleEvent(self,event):
        z = 0 + 0

class WusbEventDecoder():
    def handleEvent(self,event):
        z = 0 + 0

####################### CONTROL DISPATCHER #######################

class ControlDispatcher(Decode.ControlDecoder):
    def isUwbControlPacket(self,event):
        setup = Decode.SetupPacket(event)
        if UwbControlDescriptorGroup.requests.keys().__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0

    def isHwaControlPacket(self,event):
        setup = Decode.SetupPacket(event)
        if HwaControlDescriptorGroup.requests.keys().__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0
    def isDwaControlPacket(self,event):
        setup = Decode.SetupPacket(event)
        if DwaControlDescriptorGroup.requests.keys().__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0
    def isWaControlPacket(self,event):
        setup = Decode.SetupPacket(event)
        if WaControlDescriptorGroup.requests.keys().__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0
    def isSecurityControlPacket(self,event):
        setup = Decode.SetupPacket(event)
        if SecurityControlDescriptorGroup.requests.keys().__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0
    def isWusbControlPacket(self,event):
        rqs = (
               (0x00,0x01),
               (0x80,0x00),
               (0x00,0x05),
               (0x00,0x03),
               (0x01,0x17),
               (0x00,0x14),
               (0x00,0x13),
               (0x80,0x15),
        )
        setup = Decode.SetupPacket(event)
        if rqs.__contains__( (setup.bitmap,setup.request) ):
            return 1
        return 0


    def handleEvent(self, event):
        if not event.isDataTransaction():
            event.decoded = None
            event.decodedSummary = None
            return

        x = None
        for i in ( "Uwb", "Hwa", "Dwa", "Wa", "Wusb" ):
            q1 = getattr(self, "is%sControlPacket" % i, None )
            assert(callable(q1))
            if q1(event):
                q2 = getattr(sys.modules[globals()['__name__']],"%sControlDecoder" % i, None)
                assert(callable(q2))
                x = q2(self.device)
                if x:
                    break

        if x is not None:
            x.handleEvent(event)
            return

        ##############################################
        # Fall back to the top-level control decoder #
        ##############################################

        setup = Decode.SetupPacket(event)

        # Look up the request name
        setup.requestName = getattr(self, "%sRequests" % setup.type,
                                    Struct.EnumDict())[setup.request]

        # Look up a corresponding decoder
        d = getattr(self, "decode_%s" % setup.requestName, self.decodeGeneric)
        d(setup)

####################### DETECTOR FUNCTION ########################

def detector(context):
    # this is required for all 'Decoder' modules
    dev = context.device
    ep = context.endpoint
    ifc = context.interface
    devi = context.devInstance

# TODO: config decoder needed for pretty-printing WUSB descriptors

    if dev:
        (clazz,subclazz,proto) = (
                      dev.bDeviceClass,
                      dev.bDeviceSubClass,
                      dev.bDeviceProtocol,
                      )
    else:
        clazz = subclazz = proto = None

    # We hijack the default control decoder for wire adapter peripherals
    # so that we can do the control routing ourselves (better)
    if (clazz,subclazz,proto) == (239,2,2) and not ep:
        devi.controlDecoder = ControlDispatcher(devi)
        devi.endpointDecoders[0] = devi.controlDecoder
        return

    # Cable-Based Association interfaces get their own special treatment
    if ifc:
        (clazz,proto,subclazz) = (
            ifc.bInterfaceClass,
            ifc.bInterfaceSubClass,
            ifc.bInterfaceProtocol,
        )
        if (clazz,proto,subclazz) == (239,3,1):
# TODO: finish this off
            print 'CableBasedAssociation'

    # We respond with event decoders for interrupt endpoints
    if ifc and ep:
        (clazz,subclazz,proto,attr) = (
            ifc.bInterfaceClass,
            ifc.bInterfaceSubClass,
            ifc.bInterfaceProtocol,
            ep.bmAttributes & 0x03,
        )
        if (clazz,subclazz,proto,attr) == (224,1,2,3):
            return UwbEventDecoder()
        elif (clazz,subclazz,proto,attr) == (224,2,1,3):
# TODO: finish this off
            print 'HwaEventDecoder'
