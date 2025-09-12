#!/usr/bin/env python3
import argparse
import etao
from cc1101 import CC1101Whitening, check_crc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bytes_file', type=argparse.FileType('rb'))
    args = parser.parse_args()

    bytez = args.bytes_file.read()

    good_pkts = 0
    num_pkts = 0

    byte_i = 0

    while byte_i < len(bytez):
        len_check = bytez[byte_i] ^ 0xff
        num_pkts += 1

        pkt = bytez[byte_i:byte_i + len_check + 1 + 2]
        byte_i += len(pkt)

        whitener = CC1101Whitening()
        pkt = whitener.dewhiten(pkt)

        good_crc = check_crc(pkt)

        if good_crc:
            good_pkts += 1

        print(pkt.hex())

        crc_msg = 'good' if good_crc else 'bad'
        print(f'CRC16 check: {crc_msg}')

        print()

    good_pct = 0 if num_pkts == 0 else good_pkts / num_pkts * 100.0
    print(f'{num_pkts} packets, {good_pkts} have good CRC ({good_pct:.2f}%)')


if __name__ == '__main__':
    main()
