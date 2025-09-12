import math
from Crypto.Cipher import AES
from Crypto.Util import Counter


DEFAULT_KEY = bytearray([x for x in range(0x00, 0x10)])
DEFAULT_NONCE = bytearray([x for x in range(0xf0, 0xfc)])


def tick_round(ticks):
    """round ticks to multiples of 512 (64th of a second)"""
    return ticks & ~0x1ff


def powerg_cipher(key, nonce, time, iv=0):
    # ticks rounded to multiples of 512 (64th of a second)
    time_64ths = tick_round(time) & 0xFFFFFFFF

    counter = Counter.new(8,
        prefix=time_64ths.to_bytes(4, 'little')[1:],
        initial_value=iv,
        suffix=nonce)
    aes_ctr = AES.new(key, AES.MODE_CTR, counter=counter)

    return aes_ctr


def hop_bytes(key, hop_ctx, time, unk_flag=True):
    # ensure 32 bit value
    time &= 0xFFFFFFFF

    # there can be some variations on time based on unused boolean
    if not unk_flag:
        time &= 0xFFFFFE01

        if (hop_ctx['save_time'] & ~0xff) != (time & ~0xff):
            hop_ctx['save_time'] = time

    aes_ctr = powerg_cipher(key, b'\x00' * 12, time, iv=0xfe)

    keystream = aes_ctr.encrypt(b'\x00' * 6)

    first = keystream[4]
    second = keystream[5]

    if unk_flag:
        # check bit pos 17 and above are all the same (interval of at least 2^17 ticks, i.e. 4 seconds on 32KHz clock)
        if hop_ctx['save_output'] is not None and ((hop_ctx['save_time'] ^ time) >> 17) == 0:
            second = hop_ctx['save_output']
        else:
            hop_ctx['save_output'] = second
            hop_ctx['save_time'] = time

    return (first, second)


def hop_channels(key, hop_time, unk_flag=True):
    tmp_ctx = {
        'save_time': 0,
        'save_output': None,
    }

    hop_keystream = hop_bytes(key, tmp_ctx, hop_time)

    # use time rounded to 4 seconds for slow-changing channel ID
    tmp_ctx = {
        'save_time': 0,
        'save_output': None,
    }

    hop_time_4sec = hop_time & ~0x1ffff
    hop_keystream_4sec = hop_bytes(key, tmp_ctx, hop_time_4sec)

    return (
        hop_keystream[0] % 50,
        (hop_keystream[0] + 25) % 50,
        hop_keystream_4sec[1] % 50
        )


class PGIncompletePacketException(Exception):
    pass


class PGBadCRCException(Exception):
    pass


class PGDuplicatePacketException(Exception):
    pass


class PGDecryptException(Exception):
    pass


class PowerGNetwork:

    def __init__(self, network_id, clock=0, key=DEFAULT_KEY, nonce=DEFAULT_NONCE):
        self.network_id = network_id

        self.key = key
        self.nonce = nonce

        self.devices = {}

        # last packet info for dedupe
        self.last_src_addr = None
        self.last_dst_addr = None
        self.last_dedupe_id = None

        main_modem = self.add_device(network_id, clock=clock)
        main_modem.clock_set_time = 0.0

    def clock(self):
        return self.get_device(self.network_id).clock

    def add_device(self, addr, clock=None):
        if addr in self.devices:
            raise ValueError('device with that address already exists')

        new_dev = PowerGDevice(addr, clock, network=self)
        self.devices[addr] = new_dev

        return new_dev

    def get_device(self, addr, create_new=False):
        if addr not in self.devices and create_new:
            self.add_device(addr)

        return self.devices.get(addr, None)

    def is_duplicate_pkt(self, pkt):
        is_duplicate = False

        if pkt.src_addr == self.last_src_addr and pkt.dst_addr == self.last_dst_addr and \
            pkt.dedupe_counter == self.last_dedupe_id:
            if pkt.dst_addr != 0xff:
                dst_time = self.get_device(pkt.dst_addr).clock
            else:
                # hack: for broadcast packet, use src clock
                dst_time = self.get_device(pkt.src_addr).clock
            pkt_timestamp = pkt.get_timestamp()

            if dst_time is not None and pkt_timestamp is not None:
                # if we have the time info, check time interval
                is_duplicate = dst_time - pkt_timestamp < 0x28001
            else:
                # ignore time interval check if we can't do it
                is_duplicate = True

        self.last_src_addr = pkt.src_addr
        self.last_dst_addr = pkt.dst_addr
        self.last_dedupe_id = pkt.dedupe_counter

        return is_duplicate

    def determine_nonce(self, pkt):
        if pkt.nonce_mode == 2:
            return b'\x00' * 12
        elif pkt.nonce_mode == 3:
            return self.nonce
        else:
            return None

    def check_keystream(self, nonce, time):
        aes_ctr = powerg_cipher(self.key, nonce, time, iv=0xff)

        payload_pt = aes_ctr.encrypt(b'\x00' * 4)
        return (payload_pt[0:2], payload_pt[2:4])

    def find_clock_drift(self, pkt, start_timestamp, tolerance_sec):
        nonce = self.determine_nonce(pkt)

        # timestamp group may have rolled over
        # check +/- tolerance time (specified in seconds)
        max_retries = math.ceil(64 * 2 * tolerance_sec)

        original_timestamp = start_timestamp

        start_timestamp = (start_timestamp - (max_retries * 512) // 2) & 0xFFFFFFFF
        checks = self.check_keystream(nonce, start_timestamp)
        retries = 1

        while pkt.keystream_head not in checks and retries < max_retries:
            start_timestamp = (start_timestamp + 512) & 0xFFFFFFFF
            checks = self.check_keystream(nonce, start_timestamp)
            retries += 1

        # in some cases, second pair of bytes is used, e.g. type 0x51?
        if pkt.keystream_head in checks:
            print(f'check keystream: {checks[0].hex()} {checks[1].hex()} ({retries} increments - {(start_timestamp - original_timestamp) / 32768} seconds difference)')
            return start_timestamp
        else:
            return None

    def determine_clock(self, pkt, tolerance_sec=1.0):
        nonce = self.determine_nonce(pkt)

        select_timestamp = self.clock()
        exact_timestamp = False

        if not pkt.no_time_info:
            select_timestamp = pkt.get_timestamp()
            exact_timestamp = True
        else:
            if pkt.msg_type == 0x51:
                # when modems sends its own clock, it encrypts using destination clock
                # (could be wrong if the destination clock unexpectedly changes)
                if pkt.dst_addr == 0xff:
                    # TODO handle when it's a broadcast packet?
                    print('!!! broadcast addr clock? !!!')
                    select_timestamp = self.clock()
                else:
                    select_timestamp = self.get_device(pkt.dst_addr).clock
            else:
                select_timestamp = self.get_device(pkt.src_addr).clock

        if select_timestamp is None:
            select_timestamp = 0

        time_64ths = tick_round(select_timestamp)

        checks = self.check_keystream(nonce, select_timestamp)

        if pkt.keystream_head not in checks and exact_timestamp:
            print(f"packet timestamp {pkt.get_timestamp()} included but didn't work")

        if pkt.keystream_head not in checks and select_timestamp != self.clock():
            # try with network time if device clock didn't work
            net_clock_checks = self.check_keystream(nonce, self.clock())

            if pkt.keystream_head in net_clock_checks:
                select_timestamp = self.clock()
                checks = net_clock_checks

        if pkt.keystream_head in checks:
            return select_timestamp

        # last seen clocks didn't work, try timestamps within clock drift tolerance
        if exact_timestamp:
            # when timestamp is included in packet, probably doesn't make sense to check for clock drift
            drift_clock = None
        else:
            drift_clock = self.find_clock_drift(pkt, select_timestamp, tolerance_sec)

        # try timestamps close to network time
        if drift_clock is None and select_timestamp != self.clock():
            drift_clock = self.find_clock_drift(pkt, self.clock(), tolerance_sec)

        return drift_clock

    def decrypt_payload(self, pkt, clock_drift_tolerance_sec=1.0):
        payload = pkt.get_payload()

        if pkt.nonce_mode < 2:
            # not encrypted
            return (payload, None)

        nonce = self.determine_nonce(pkt)

        select_timestamp = self.determine_clock(pkt, tolerance_sec=clock_drift_tolerance_sec)

        if select_timestamp is None:
            raise PGDecryptException('keystream check failed')

        aes_ctr = powerg_cipher(self.key, nonce, select_timestamp)
        payload_pt = aes_ctr.decrypt(payload)

        return (payload_pt, select_timestamp)


class PowerGDevice:

    def __init__(self, addr, clock, network=None):
        if addr == 0xff:
            raise ValueError('address 0xFF reserved for broadcast')
        elif addr < 0 or addr > 255:
            raise ValueError('invalid address')

        self.rf_addr = addr
        self.clock = clock
        self.clock_set_time = None
        self.network = network
