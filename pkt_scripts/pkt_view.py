#!/usr/bin/env python3
import argparse
import functools
import json
from hexdump import hexdump
from cc1101 import crc16_cc1101
from powerg_packet import PowerGPacket
from powerg_device import (PowerGNetwork, PowerGDevice,
        PGDecryptException, PGDuplicatePacketException, PGIncompletePacketException, PGBadCRCException,
        DEFAULT_KEY, DEFAULT_NONCE,
        tick_round, hop_channels)
from powerg_phy import channel_index, PREAMBLE, SYNC_WORD
from fhss_csv_parse import load_packets_csv


# PowerG device info (clock & config)
global_network = None


def get_bit_field(value, start, length):
    if value < 0 or value > 255:
        raise Exception()

    if length < 1 or length > 8:
        raise Exception()

    length_mask = 2**length - 1
    return (value >> start) & length_mask


def print_bit_field(name, buf, idx, start, length):
    value = buf[idx]
    field = get_bit_field(value, start, length)
    print(f'{name}:\tbyte {idx}[{start+length-1}:{start}] =\t{field}')
    return field


def msg_handle_hdr_51_71(pkt_json, pkt, payload_pt):
    # types 0x51 / 0x71 first bytes
    pkt_info_bit = get_bit_field(payload_pt[0], 7, 1)
    rssi = get_bit_field(payload_pt[0], 0, 7) << 1
    network_topology = payload_pt[1]

    return {
        'rssi_thing': rssi,
        'network_topology': network_topology,
        'pkt_info_bit': pkt_info_bit,
    }


def msg_handle_time(pkt_json, pkt, payload_pt):
    """RF msg type 0x51"""
    global global_network

    pkt_real_time = pkt_json['metadata']['start_time']

    details = msg_handle_hdr_51_71(pkt_json, pkt, payload_pt)

    modem_timestamp = int.from_bytes(payload_pt[2:6], 'little')

    details['modem_timestamp'] = modem_timestamp

    src_dev = global_network.get_device(pkt.src_addr)
    src_dev.clock = modem_timestamp
    src_dev.clock_set_time = pkt_real_time

    if pkt.dst_addr != 0xff:
        dst_dev = global_network.get_device(pkt.dst_addr)
        dst_dev.clock = modem_timestamp
        dst_dev.clock_set_time = pkt_real_time
    else:
        # if it's a broadcast packet, set every device clock
        for device in global_network.devices:
            device.clock = modem_timestamp
            device.clock_set_time = pkt_real_time

    return details


def msg_handle_data(pkt_json, pkt, payload_pt):
    details = {}

    if len(payload_pt) >= 6:
        details['long_id'] = payload_pt[3:6]

    return details


def msg_handle_key(pkt_json, pkt, payload_pt):
    """RF msg type 0x71"""
    global global_network

    details = msg_handle_hdr_51_71(pkt_json, pkt, payload_pt)

    initial_keystream_head = payload_pt[2:4]
    primary_key = payload_pt[4:20]
    global_network.key = primary_key

    details['initial_keystream_head'] = initial_keystream_head
    details['primary_key'] = primary_key

    return details


def msg_handle_nonce(pkt_json, pkt, payload_pt):
    """RF msg type 0x73"""
    global global_network

    keystream_head_copy = payload_pt[11:13]
    key_copy = payload_pt[13:29]
    modem_nonce = payload_pt[29:41]
    global_network.nonce = modem_nonce

    return {
        'keystream_head_copy': keystream_head_copy,
        'key_copy': key_copy,
        'modem_nonce': modem_nonce,
    }


MSG_HANDLERS = {
    0x51: msg_handle_time,
    0x52: msg_handle_data,
    0x71: msg_handle_key,
    0x73: msg_handle_nonce,
}


def pkt_msg_details(pkt_json, pkt, payload_pt):
    handler = MSG_HANDLERS.get(pkt.msg_type, None)

    if handler is not None:
        return handler(pkt_json, pkt, payload_pt)

    return None


def pkt_info(pkt_json, show_raw=False, skip_bad_crc=True, skip_dupes=True, clock_drift_tolerance_sec=1.0):
    global global_network

    data = pkt_json['data']
    metadata = pkt_json['metadata']

    # remove preamble & sync word
    data = data.lstrip(PREAMBLE)
    data = data.lstrip(SYNC_WORD)

    if len(data) < 13:
        raise PGIncompletePacketException(f'not enough bytes ({len(data)})')

    pkt = PowerGPacket(data)

    check_crc = pkt.check_crc()
    expected_crc = crc16_cc1101(bytes(pkt)[:-2])

    if skip_bad_crc and not check_crc:
        raise PGBadCRCException()

    rf_pkt_len = pkt.length + 1
    payload_ct = pkt.get_payload()

    # look up devices
    src_dev = global_network.get_device(pkt.src_addr, create_new=True)

    if pkt.dst_addr != 0xff:
        dst_dev = global_network.get_device(pkt.dst_addr, create_new=True)

    hop_time = None

    # use time info to track each device's clock
    timestamp = pkt.get_timestamp()
    if timestamp is not None:
        src_dev.clock = timestamp
        src_dev.clock_set_time = metadata['start_time']
        hop_time = timestamp
        time_delta = None
    elif src_dev.clock is not None and src_dev.clock_set_time is not None:
        # convert time diff in seconds to 32KHz clock ticks
        time_delta = round((metadata['start_time'] - src_dev.clock_set_time) * 32768)

        # adjust the device clock
        src_dev.clock += time_delta
        src_dev.clock_set_time = metadata['start_time']

        hop_time = src_dev.clock

    if global_network.is_duplicate_pkt(pkt):
        if skip_dupes:
            raise PGDuplicatePacketException(f'*duplicate packet* (timestamp: {hop_time})')

    # handle encrypted packet data
    decryption_exception = None

    try:
        payload, clock = global_network.decrypt_payload(pkt, clock_drift_tolerance_sec=clock_drift_tolerance_sec)
        if clock is not None:
            hop_time = clock
    except PGDecryptException as e:
        payload = None
        clock = None
        decryption_exception = e

    # get expected channel IDs per hop config
    if hop_time is not None:
        channels = hop_channels(global_network.key, hop_time)
    else:
        channels = None

    if decryption_exception is None:
        # remove plaintext timestamp (TODO: what about the 2 unknown bytes?)
        if not pkt.no_time_info:
            payload = payload[:-4]

        details = pkt_msg_details(pkt_json, pkt, payload)
    else:
        details = None

    return {
        'scapy_pkt': pkt,
        'payload': payload,
        'msg_details': details,

        'good_crc': check_crc,
        'expected_crc': expected_crc,

        'time_delta': time_delta,
        'decrypt_clock': clock,
        'hop_time': hop_time,
        'channels': channels,
    }


def load_packets_json(data_file):
    for line in data_file:
        line = line.rstrip('\n')
        if line == '':
            continue

        pkt_json = json.loads(line)
        pkt_json['data'] = bytes.fromhex(pkt_json['data'])
        yield pkt_json


def pkt_quick_display(packet, pkt_data):
    pkt = pkt_data['scapy_pkt']

    if pkt_data['payload'] is None:
        display_payload = pkt.get_payload()
        note = ' (decrypt failed)'
    else:
        display_payload = pkt_data['payload']
        note = ''

    print(f'quick: {pkt.src_addr:#04x} -> {pkt.dst_addr:#04x}/{pkt.addr_related:#04x} type {pkt.msg_type:#04x}, payload: {display_payload.hex()}{note}')


def main():
    global global_network

    parser = argparse.ArgumentParser()
    parser.add_argument('data_file', type=argparse.FileType('r'))
    parser.add_argument('--key', type=str)
    parser.add_argument('--nonce', type=str)
    parser.add_argument('--time-brute-force', action='store_true', default=False)
    parser.add_argument('--show-raw', action='store_true', default=False)
    parser.add_argument('--start-time', type=int, default=0)
    parser.add_argument('--clock-drift-tolerance', type=float, default=2.0, help='clock drift tolerance (in seconds)')
    parser.add_argument('--network-id', type=int, default=1, help='network ID (address of main modem)')
    parser.add_argument('--quick', action='store_true', default=False, help='quick packet view')
    parser.add_argument('--show-dup', action='store_true', default=False)
    args = parser.parse_args()

    fn_lower = args.data_file.name.lower()
    if fn_lower.endswith('.json'):
        packet_gen = functools.partial(load_packets_json, args.data_file)
    elif fn_lower.endswith('.csv'):
        packet_gen = functools.partial(load_packets_csv, args.data_file, remove_syncword=False)
    else:
        print('data file must be .json or .csv')
        return

    global_network = PowerGNetwork(args.network_id, clock=args.start_time)

    if args.key is not None:
        global_network.key = bytes.fromhex(args.key)

    if args.nonce is not None:
        global_network.nonce = bytes.fromhex(args.nonce)

    if args.time_brute_force:
        # 23 bit network clock counting 64ths of a second
        # given as +/- tolerance so divide by 2
        tolerance_sec = ((2**23 - 1) * 64) / 2
        # TODO also use channel ID to check result
    else:
        tolerance_sec = args.clock_drift_tolerance

    for packet in packet_gen():
        try:
            pkt_data = pkt_info(packet, show_raw=args.show_raw, clock_drift_tolerance_sec=tolerance_sec, skip_dupes=not args.show_dup)
        except (PGDecryptException, PGIncompletePacketException, PGDuplicatePacketException, PGBadCRCException) as pge:
            if not args.quick:
                print(f'{type(pge).__name__}: {pge}')
            continue

        if args.quick:
            pkt_quick_display(packet, pkt_data)
            continue

        print('=' * 80)
        if args.show_raw:
            print('== RAW DATA ==')
            hexdump(packet['data'])
            print()

        print('== METADATA ==')
        metadata = packet['metadata']
        chan_id = channel_index(metadata['center_frequency'])
        print(f'Packet on channel {chan_id:02} (Burst center frequency: {round(metadata["center_frequency"]):,} Hz)')
        print(f'Start time: {metadata["start_time"]}')
        # start_time_offset is included in PDU output but looks like it's already factored into start_time
        # https://github.com/sandialabs/gr-pdu_utils/blob/68984503712114bbabb4d6b8814d3997144f025b/lib/pdu_align_impl.cc#L133

        if pkt_data is None:
            continue

        pkt = pkt_data['scapy_pkt']
        rf_pkt_len = pkt.length + 1
        payload_ct = pkt.get_payload()

        crc_detail = "GOOD" if pkt_data['good_crc'] else f'BAD (should be {pkt_data["expected_crc"]:#06x})'
        print(f'CRC-16 (CC1101): {pkt.crc:#06x} {crc_detail}')
        print()

        print(f'time delta: {pkt_data["time_delta"]} -> {pkt_data["hop_time"]} ({tick_round(pkt_data["hop_time"])} rounded to 1/64s)')
        print()

        if not pkt.no_time_info:
            print('== TIMESTAMP ==')
            print(f'included timestamp: {pkt.get_timestamp()}  ({tick_round(pkt.get_timestamp())} rounded to 1/64s)')

            unknown_bytes = payload_ct[-6:-4]
            unknown = int.from_bytes(unknown_bytes, 'little')
            print(f'unknown 2 bytes before timestamp: {unknown} ({unknown:#06x})')
            print()

        if pkt.nonce_mode >= 2 and pkt_data['decrypt_clock'] is not None:
            clock = pkt_data['decrypt_clock']
            print('== DECRYPTION ==')
            print(f'decryption clock: {clock} ({tick_round(clock)} rounded to 1/64s)')
            print()

        if pkt_data['channels'] is not None:
            print('== CHANNEL HOPPING ==')
            print(f'default channel: 15')

            for i, chan in enumerate(pkt_data['channels']):
                print(f'hop config {i} channel: {chan}')

            print()

        print('== HEADER ==')
        print(f'Packet length: {rf_pkt_len} ({pkt.length:#04x} + 1)')
        print(f'Payload length: {rf_pkt_len - 10 - 1}')  # subtract header and EOM null bytes
        print(f'Src addr: {pkt.src_addr:#04x}')
        print(f'Dst addr: {pkt.dst_addr:#04x}')
        print(f'??? addr: {pkt.addr_related:#04x}')
        print()

        print('Bit field bytes:')
        for i in range(4, 7):
            print(f'{i}: {bytes(pkt)[i]:08b} ({bytes(pkt)[i]:#04x})')
        print()

        # print bit fields
        # byte 4
        print(f'dedupe counter:\t{pkt.dedupe_counter}')
        print(f'notification period?:\t{pkt.notification_period_maybe}')

        # byte 5
        print(f'no time info:\t{pkt.no_time_info}')
        print(f'byte 5 bit 1:\t{pkt.byte5_bit1}')
        print(f'nonce mode:\t{pkt.nonce_mode}')
        tx_power_enum = PowerGPacket.tx_power.i2s[pkt.tx_power]
        print(f'Tx power:\t{pkt.tx_power} -> {tx_power_enum} dBm')

        print(f'byte 6 bit 7:\t{pkt.byte6_bit7}')
        print(f'byte 6 bit 6:\t{pkt.byte6_bit6}')
        print(f'byte 6 bit 5-4:\t{pkt.byte6_bit5_4}')
        print(f'byte 6 bit 3:\t{pkt.byte6_bit3}')
        print(f'byte 6 bit 2-0:\t{pkt.byte6_bit2_0}')

        print()

        print(f'RF message type: {pkt.msg_type:#04x}')
        print(f'Keystream head: {pkt.keystream_head.hex()}')
        print(f'Nonce/crypto mode: {pkt.nonce_mode}')

        print()

        print('== BODY ==')
        print('Payload:')
        hexdump(payload_ct)
        print()

        if pkt.nonce_mode >= 2 and pkt_data['payload'] is not None:
            print('Decrypted payload:')
            hexdump(pkt_data['payload'])
            print()

        if pkt_data['msg_details'] is not None:
            print('== DETAILS ==')
            for key, val in pkt_data['msg_details'].items():
                if type(val) is int:
                    val_str = f'{val:#x}'
                elif type(val) is bytes:
                    val_str = val.hex()
                else:
                    val_str = str(val)

                print(f'{key}: {val_str}')
            print()


if __name__ == '__main__':
    main()
