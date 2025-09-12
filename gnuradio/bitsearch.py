#!/usr/bin/env python3
import argparse
import etao
from cc1101 import CC1101Whitening, check_crc
from crc import Calculator, Configuration


def to_bits(x):
    x = x & 0xFFFFFFFF
    bit_string = f'{x:032b}'
    return bit_string


def extract_pkt(bit_string):
    end_i = (len(bit_string)//8) * 8
    bit_string = bit_string[:end_i]

    bytez = etao.bits_to_bytes(bit_string)[4:]

    # get packet length
    whitener = CC1101Whitening()
    pkt_data = whitener.dewhiten(bytez[0:1])

    # pkt len doesn't include self, or the 2 CRC-16 bytes
    pkt_len = int.from_bytes(pkt_data, 'big') + 1

    print(f'pkt len: {pkt_len}')

    pkt_data += whitener.dewhiten(bytez[1:pkt_len + 2])

    return pkt_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bits_file', type=argparse.FileType('rb'))
    args = parser.parse_args()

    bits = args.bits_file.read()

    print(f'read {len(bits)} bits')

    bits = ''.join([str(x) for x in bits])
    #print(bits)

    sync_word = 0x1F351F35
    sync_word_bits = to_bits(sync_word)

    start_i = 0
    next_i = 0

    num_pkts = 0
    good_pkts = 0

    while start_i < len(bits):
        next_i = bits.find(sync_word_bits, start_i)
        if next_i == -1:
            break

        num_pkts += 1

        pkt = extract_pkt(bits[next_i:])

        print(f'found sync word at {next_i}')
        print(pkt.hex())

        good_crc = check_crc(pkt)

        if good_crc:
            good_pkts += 1
            start_i = next_i + len(pkt)
        else:
            start_i = next_i + 1

        crc_msg = 'good' if good_crc else 'bad'
        print(f'CRC16 check: {crc_msg}')

        print()

    good_pct = 0 if num_pkts == 0 else good_pkts / num_pkts * 100.0
    print(f'{num_pkts} packets, {good_pkts} have good CRC ({good_pct:.2f}%)')


if __name__ == '__main__':
    main()
