#!/usr/bin/env python3
import etao
from crc import Calculator, Configuration


CRC_CONFIG = Configuration(
    width=16,
    polynomial=0x8005,
    init_value=0xffff,
    final_xor_value=0x0000,
    reverse_input=False,
    reverse_output=False,
)

CRC16_CC1101 = Calculator(CRC_CONFIG)


class CC1101Whitening:

    def __init__(self, polynomial=0x21):
        self.polynomial = polynomial

        self.polynomial_bits = [0] + \
            etao.bytes_to_bits(self.polynomial.to_bytes(1, 'big'))

        self.poly_len = len(self.polynomial_bits)

        self.lfsr_state = 2**self.poly_len - 1
        self.lfsr_mask = self.lfsr_state >> 1

        self.first_use = True

    def _lfsr(self, clock):
        for i in range(clock):
            first_bit = 0

            flips = self.polynomial & self.lfsr_state

            while flips != 0:
                first_bit ^= flips & 1
                flips >>= 1

            self.lfsr_state >>= 1

            if first_bit == 1:
                self.lfsr_state |= 1 << (self.poly_len - 1)

        return self.lfsr_state & self.lfsr_mask

    def _apply(self, data, decode=True):
        # TODO: "crop last bit if duplicate"

        keystream = bytearray()

        if self.first_use:
            keystream.append(self._lfsr(0))
            self.first_use = False

        for i in range(len(data) - len(keystream)):
            keystream.append(self._lfsr(8))

        return etao.xor_bytes(data, keystream)

    def dewhiten(self, data):
        return self._apply(data, decode=True)

    def whiten(self, data):
        return self._apply(data, decode=False)


def crc16_cc1101(data):
    return CRC16_CC1101.checksum(data)


def check_crc(data):
    calc_crc = crc16_cc1101(data[:-2])
    pkt_crc = int.from_bytes(data[-2:], 'big')

    return calc_crc == pkt_crc


PREGEN_DEWHITEN = bytes.fromhex('ffe11d9aed853324ea7ad2397097570a547d2dd86d0dba8f6759c7a2bf34ca18305393df92eca7158adcf486554e182140c4c4d5c6918acde7d14e093217df83fff00ecdf6c21912753de91cb8cb2b05aabe16ecb606ddc7b3ac63d15f1a650c98a9c96f49f6d30a456e7ac32a278c102062e26ae348c5e6f368a704998befc17f7887667be10c89ba9e740edce59502555f0b765b83eee359d6b1e82f8d3206ccd4e4b724fb69852237bd6195134608103171b571a462f379b45382ccc5f7e03fbc43b3bd7086445d4f3a07eef24a81aaaf05bbad41f7f12ceb58f497461903666af25b92fdb442919bdeb0ca0923048898b8da3852b1f93cda2941e6e27bf01fdea1d9')
PREGEN_LEN = len(PREGEN_DEWHITEN)

def fast_dewhiten(data):
    if len(data) > PREGEN_LEN:
        raise Exception(f'pre-generated keystream only has {PREGEN_LEN} bytes')

    return etao.xor_bytes(data, PREGEN_DEWHITEN)


def main():
    test_pkt =  bytes.fromhex('1f351f35e8e917678d8b33a4ab914995af80fb73d0a127d86d07ba8fae33')
    check_pkt = bytes.fromhex('1f351f3517080afd600e008041eb9bacdf17ac7984dc0a00000a0000c96a')

    whitener = CC1101Whitening()
    dewhitened = whitener.dewhiten(test_pkt[4:])

    print(f'incoming packet: {test_pkt.hex()}')
    print(f'dewhitened:\t{dewhitened.hex()}')
    print(f'check data:\t{check_pkt[4:].hex()}')

    print(f'match: {dewhitened == check_pkt[4:]}')

    print(f'CRC good: {check_crc(dewhitened)}')

    # whitening keystream is not data dependent
    print('\n*testing with pre-generated whitening keystream*')
    dewhitened = fast_dewhiten(test_pkt[4:])

    print(f'incoming packet: {test_pkt.hex()}')
    print(f'dewhitened:\t{dewhitened.hex()}')
    print(f'check data:\t{check_pkt[4:].hex()}')

    print(f'match: {dewhitened == check_pkt[4:]}')

    print(f'CRC good: {check_crc(dewhitened)}')


if __name__ == '__main__':
    main()
