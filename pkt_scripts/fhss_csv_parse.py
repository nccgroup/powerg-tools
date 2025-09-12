#!/usr/bin/env python3
import argparse
import csv
import etao
import json
from cc1101 import CC1101Whitening, check_crc
from powerg_phy import PREAMBLE, SYNC_WORD


TYPES_MAP = {
    'double': float,
    'uint64': int,
}

METADATA_CHECK_ROW = set('start_offset(uint64), start_time(double), start_time_offset(double), center_frequency(double)'.split(', '))

METADATA_MAP = {
    i: {
        'name': val,
        'output_name': val.split('(')[0],
        'data_type': TYPES_MAP[val.split('(')[1].rstrip(')')],
    } for i, val in enumerate(METADATA_CHECK_ROW)
}


def load_packets_csv(csv_file, as_bits=False, dewhiten=False, remove_syncword=False, verbose=False):
    reader = csv.DictReader(csv_file, restkey='data')

    # make sure required fields are present
    assert METADATA_CHECK_ROW.issubset(set(reader.fieldnames))

    for row in reader:
        data_cols = row['data']

        pkt_metadata = {}

        for idx, info in METADATA_MAP.items():
            pkt_metadata[info['output_name']] = info['data_type'](row[info['name']])

        if as_bits:
            bit_len = len(data_cols)
            if bit_len % 8 != 0:
                if verbose:
                    print(f'truncating {bit_len % 8} bits')
                trunc_end = bit_len - (bit_len % 8)
                data_cols = data_cols[:trunc_end]

            row_bytes = etao.bits_to_bytes(data_cols)
        else:
            row_bytes = bytes([int(x) for x in data_cols])

        if remove_syncword:
            # remove sync word
            row_bytes = row_bytes.lstrip(SYNC_WORD)

        if len(row_bytes) == 0:
            continue

        burst_len = len(row_bytes)

        if dewhiten:
            pkt_len = (row_bytes[0] ^ 0xFF) + 3
        else:
            pkt_len = row_bytes[0] + 3

        if len(row_bytes) < pkt_len:
            if verbose:
                print('incomplete burst')
        elif len(row_bytes) > pkt_len:
            extra = len(row_bytes) - pkt_len
            if verbose:
                print(f'removing {extra} extra bytes')
            row_bytes = row_bytes[:-extra]

        if dewhiten:
            whitener = CC1101Whitening()
            pkt = whitener.dewhiten(row_bytes)
        else:
            pkt = row_bytes

        pkt_data = {
            'metadata': pkt_metadata,
            'data': pkt,
            'burst_len': burst_len,
        }

        yield pkt_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_file', type=argparse.FileType('r'))
    parser.add_argument('--wsw', action='store_true', default=False, help='sync word bits included')
    parser.add_argument('--dewhiten', action='store_true', default=False, help='apply CC1101 dewhitening')
    parser.add_argument('--bits', action='store_true', default=False, help='CSV values are bits instead of bytes')
    args = parser.parse_args()

    num_pkts = 0
    good_pkts = 0

    for pkt_data in load_packets_csv(args.csv_file, as_bits=args.bits, dewhiten=args.dewhiten, remove_syncword=args.wsw):
        num_pkts += 1
        pkt = pkt_data['data']

        good_crc = check_crc(pkt)
        if good_crc:
            good_pkts += 1

        print(f'pkt len w/ CRC: {len(pkt)}, burst len: {pkt_data["burst_len"]}')

        print(f'CRC good: {good_crc}')

        print(pkt_data['metadata'])
        print(pkt.hex())

        print()

    good_pct = 0 if num_pkts == 0 else good_pkts / num_pkts * 100.0
    print(f'{num_pkts} packets, {good_pkts} have good CRC ({good_pct:.2f}%)')


if __name__ == '__main__':
    main()
