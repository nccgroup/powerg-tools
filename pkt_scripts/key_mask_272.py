#!/usr/bin/env python3
import argparse


rand_outputs = [1804289383,846930886,1681692777,1714636915,
        1957747793,424238335,719885386,1649760492,
        596516649,1189641421,1025202362,1350490027,
        783368690,1102520059,2044897763,1967513926,
        1365180540,1540383426,304089172,1303455736,
        35005211,521595368,294702567,1726956429,
        336465782,861021530,278722862,233665123,
        2145174067,468703135,1101513929,1801979802,
        1315634022,635723058,1369133069,1125898167]
rand_i = 0


def rand():
    global rand_outputs
    global rand_i

    result = rand_outputs[rand_i]
    rand_i += 1
    return result


def u32(x):
    return x & 0xffffffff


def main():
    global rand_outputs
    global rand_i

    parser = argparse.ArgumentParser()
    parser.add_argument('serial', type=str, help='Panel serial number (16 characters)')
    parser.add_argument('--offset', type=int, default=0, help='starting offset in rand() output sequence')
    args = parser.parse_args()

    assert len(args.serial) == 16

    rand_i = args.offset
    serial = args.serial.encode('ascii')

    print(f'Serial:\t{args.serial}')
    print(f'Serial hex:\t{serial.hex()}')

    primary_key = b''
    for eep_sn_i in range(15, -1, -1):
        cur_byte = serial[eep_sn_i]
        masked_byte = u32(cur_byte * rand()) % 0xff

        primary_key += bytes([masked_byte])

    assert len(primary_key) == 16
    print(f'Primary key:\t{primary_key.hex()}')

    secondary_key = b''
    for eep_sn_i in range(15, 3, -1):
        cur_byte = serial[eep_sn_i]
        masked_byte = u32(cur_byte * rand()) % 0xff

        secondary_key += bytes([masked_byte])

    assert len(secondary_key) == 12
    print(f'Secondary key:\t{secondary_key.hex()}')


if __name__ == '__main__':
    main()
