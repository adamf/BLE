# BLE scanner, based on https://code.google.com/p/pybluez/source/browse/trunk/examples/advanced/inquiry-with-rssi.py

# https://github.com/pauloborges/bluez/blob/master/tools/hcitool.c for lescan
# https://kernel.googlesource.com/pub/scm/bluetooth/bluez/+/5.6/lib/hci.h for opcodes
# https://github.com/pauloborges/bluez/blob/master/lib/hci.c#L2782 for functions used by lescan

# performs a simple device inquiry, followed by a remote name request of each
# discovered device


# TODO(adamf) make sure all sizes in the struct.pack() calls match the correct types in hci.h
# and that we're not padding with 0x0 when we should be using an unsigned short

# NOTE: Python's struct.pack() will add padding bytes unless you make the endianness explicit. Little endian
# should be used for BLE. Always start a struct.pack() format string with "<"

import os
import sys
import struct
import bluetooth._bluetooth as bluez

LE_PUBLIC_ADDRESS=0x00
LE_RANDOM_ADDRESS=0x01
LE_SET_SCAN_PARAMETERS_CP_SIZE=7
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_PARAMETERS=0x000B
OCF_LE_SET_SCAN_ENABLE=0x000C
OCF_LE_CREATE_CONN=0x000D

# these are actually subevents of LE_META_EVENT
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02
EVT_LE_CONN_UPDATE_COMPLETE=0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE=0x04

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])
    print 

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr: 
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)


# BLE and bluetooth use the same disconnect command.
#def hci_disconnect(sock, reason=bluez.HCI_OE_USER_ENDED_CONNECTION):
#    pass
    
def hci_connect_le(sock, peer_bdaddr, interval=0x0004, window=0x004,
                   initiator_filter=0x0, peer_bdaddr_type=LE_RANDOM_ADDRESS, 
                   own_bdaddr_type=0x00, min_interval=0x000F, max_interval=0x000F,
                   latency=0x0000, supervision_timeout=0x0C80, min_ce_length=0x0001,
                   max_ce_length=0x0001):

#    interval = htobs(0x0004);
#        window = htobs(0x0004);
#        own_bdaddr_type = 0x00;
#        min_interval = htobs(0x000F);
#        max_interval = htobs(0x000F);
#        latency = htobs(0x0000);
#        supervision_timeout = htobs(0x0C80);
#        min_ce_length = htobs(0x0001);
#        max_ce_length = htobs(0x0001);
#
#        err = hci_le_create_conn(dd, interval, window, initiator_filter,
#                        peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
#                        max_interval, latency, supervision_timeout,
#                        min_ce_length, max_ce_length, &handle, 25000);
# uint16_t        interval;
#        uint16_t        window;
#        uint8_t         initiator_filter;
#        uint8_t         peer_bdaddr_type;
#        bdaddr_t        peer_bdaddr;
#        uint8_t         own_bdaddr_type;
#        uint16_t        min_interval;
#        uint16_t        max_interval;
#        uint16_t        latency;
#        uint16_t        supervision_timeout;
#        uint16_t        min_ce_length;
#        uint16_t        max_ce_length;    
    package_bdaddr = get_packed_bdaddr(peer_bdaddr)
    cmd_pkt = struct.pack("<HHBB", interval, window, initiator_filter, peer_bdaddr_type)
    cmd_pkt = cmd_pkt + package_bdaddr
    cmd_pkt = cmd_pkt + struct.pack("<BHHHHHH", own_bdaddr_type, min_interval, max_interval, latency,
                                     supervision_timeout, min_ce_length, max_ce_length)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_CREATE_CONN, cmd_pkt)
        

def hci_enable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x01)

def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)

def hci_toggle_le_scan(sock, enable):
    print "toggle scan: ", enable
# hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
# memset(&scan_cp, 0, sizeof(scan_cp));
 #uint8_t         enable;
 #       uint8_t         filter_dup;
#        scan_cp.enable = enable;
#        scan_cp.filter_dup = filter_dup;
#
#        memset(&rq, 0, sizeof(rq));
#        rq.ogf = OGF_LE_CTL;
#        rq.ocf = OCF_LE_SET_SCAN_ENABLE;
#        rq.cparam = &scan_cp;
#        rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
#        rq.rparam = &status;
#        rq.rlen = 1;

#        if (hci_send_req(dd, &rq, to) < 0)
#                return -1;
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)
    print "sent toggle enable"


def hci_le_set_scan_parameters(sock):
    print "setting up scan"
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    print "got old filter"

    SCAN_RANDOM = 0x01
    OWN_TYPE = SCAN_RANDOM
    SCAN_TYPE = 0x01
    
# pack all these
# uint8_t         type;
#        uint16_t        interval;
#        uint16_t        window;
#        uint8_t         own_bdaddr_type;
#        uint8_t         filter;

#        memset(&param_cp, 0, sizeof(param_cp));
#        param_cp.type = type;
#        param_cp.interval = interval;
#        param_cp.window = window;
#        param_cp.own_bdaddr_type = own_type;
#        param_cp.filter = filter;
#
#        memset(&rq, 0, sizeof(rq));

# #define OGF_LE_CTL              0x08
#        rq.ogf = OGF_LE_CTL;

# #define OCF_LE_SET_SCAN_PARAMETERS              0x000B
#        rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;

#        rq.cparam = &param_cp;
# #define LE_SET_SCAN_PARAMETERS_CP_SIZE 7
#        rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
#        rq.rparam = &status;
#        rq.rlen = 1;
# if (hci_send_req(dd, &rq, to) < 0)


    INTERVAL = 0x10
    WINDOW = 0x10
    FILTER = 0x00 # all advertisements, not just whitelisted devices
    # interval and window are uint_16, so we pad them with 0x0
    cmd_pkt = struct.pack("<BBBBBBB", SCAN_TYPE, 0x0, INTERVAL, 0x0, WINDOW, OWN_TYPE, FILTER)
    print "packed up: ", cmd_pkt
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
    print "sent scan parameters command"

#    pkt = sock.recv(255)
##    print "socked recieved"
#    status,mode = struct.unpack("xxxxxxBB", pkt)
#    print status

def device_inquiry_with_with_rssi(sock):
    # save current filter
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
    print "setup inquiry filter"

    duration = 4
    max_responses = 255
    cmd_pkt = struct.pack("<BBBBB", 0x33, 0x8b, 0x9e, duration, max_responses)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_INQUIRY, cmd_pkt)

    results = []

    done = False
    LE_META_EVENT = 0x3e
    while not done:
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            pkt = pkt[3:]
            nrsp = struct.unpack("B", pkt[0])[0]
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                rssi = struct.unpack("b", pkt[1+13*nrsp+i])[0]
                results.append( ( addr, rssi ) )
                print "[%s] RSSI: [%d]" % (addr, rssi)
        elif event == LE_META_EVENT:
            print "LE META EVENT"
            subevent, = struct.unpack("B", pkt[3])
            print "subevent: 0x%02x" % subevent
            if subevent == EVT_LE_CONN_COMPLETE:
                print "connection complete"
                le_handle_connectioin_complete(pkt)
                printpacket(pkt)
            elif subevent == EVT_LE_ADVERTISING_REPORT:
                print "advertising report"
                printpacket(pkt)
            elif subevent == EVT_LE_CONN_UPDATE_COMPLETE:
                print "connection updated"
                printpacket(pkt)
            elif subevent == EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
                print "read remote used features complete"
            else:
                print "unknown subevent"
            pkt = pkt[3:]
            nrsp = struct.unpack("B", pkt[0])[0]
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                rssi = struct.unpack("b", pkt[1+13*nrsp+i])[0]
                results.append( ( addr, rssi ) )
                print "[%s] RSSI: [%d]" % (addr, rssi)
        elif event == bluez.EVT_INQUIRY_COMPLETE:
            done = True
        elif event == bluez.EVT_CMD_STATUS:
            status, ncmd, opcode = struct.unpack("BBH", pkt[3:7])
            if status != 0:
                print "uh oh..."
                printpacket(pkt[3:7])
                done = True
        elif event == bluez.EVT_INQUIRY_RESULT:
            pkt = pkt[3:]
            nrsp = struct.unpack("B", pkt[0])[0]
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                results.append( ( addr, -1 ) )
                print "[%s] (no RRSI)" % addr
        elif event == bluez.EVT_CMD_COMPLETE:
            ncmd, opcode = struct.unpack("BB", pkt[4:6])
            printpacket(pkt[4:7])
            print "command complete: cmd: 0x%02x opcode: 0x%02x" % (ncmd, opcode)
        else:
            print "unknown packet, event 0x%02x " % event
            printpacket(pkt)
            print "unrecognized packet type 0x%02x" % ptype
	    print "event ", event


    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

    return results

def le_handle_connectioin_complete(pkt):
    printpacket(pkt)
    pkt = pkt[4:]
    printpacket(pkt)
    printpacket(pkt[0:5])
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    print len(pkt[11:])
    interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])
    print "status: 0x%02x\nhandle: 0x%02x" % (status, handle)
    print "role: 0x%02x\n" % role
    #print role, peer_bdaddr_type, interval, latency, supervision_timeout, master_clock_accuracy

dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print "error accessing bluetooth device..."
    sys.exit(1)

#hci_le_set_scan_parameters(sock)
#hci_enable_le_scan(sock)
#hci_disable_le_scan(sock)
hci_connect_le(sock, "FA:D1:A4:C3:75:9B")
device_inquiry_with_with_rssi(sock)

