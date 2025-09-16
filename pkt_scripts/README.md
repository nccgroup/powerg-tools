# PowerG Packet Scripts

## Setup

```console
$ python3 -m venv venv
$ . venv/bin/activate
$ pip3 install -r requirements.txt
```

## Usage

Use the `pkt_view.py` script with CSV or JSON output from the GNU Radio PowerG packet capture project. Example captures are included in the `data` directory.

Example quick packet view:

```console
$ ./pkt_view.py --quick data/door_pairing_jun_25_2024.json
quick: 0x0a -> 0x01/0xfd type 0x80, payload: 500908
quick: 0x0a -> 0x02/0xfd type 0x80, payload: 500a08
quick: 0x0a -> 0x03/0xfd type 0x80, payload: 500b08
quick: 0x0a -> 0x04/0xfd type 0x80, payload: 500c08
quick: 0x0a -> 0x05/0xfd type 0x80, payload: 500d08
quick: 0x0a -> 0x06/0xfd type 0x80, payload: 500e08
quick: 0xfe -> 0x01/0xfd type 0x76, payload: 1c77e6000028000b01032d13140100110103290110031000000000000124120022610000000207007024350461000f08
quick: 0xfe -> 0x02/0x01 type 0x76, payload: 1c77e6000028000b01032d13140100110103290110031000000000000124120022610000000207007024350461000f08
quick: 0xfe -> 0x03/0x01 type 0x76, payload: 1c77e6000028000b01032d13140100110103290110031000000000000124120022610000000207007024350461000f08
quick: 0xfe -> 0x04/0x01 type 0x76, payload: 1c77e6000028000b01032d13140100110103290110031000000000000124120022610000000207007024350461000f08
quick: 0xfe -> 0x05/0x01 type 0x76, payload: 1c77e6000028000b01032d13140100110103290110031000000000000124120022610000000207007024350461000f08
...
```

`pkt_view.py` can automatically detect network keys in captures that include the pairing process. If the pairing process is not present in a capture,
use the `--key` and `--nonce` options to use known values for packet decryption.

For example, using the keys captured from `door_pairing_jun_25_2024.json`:

```console
$ ./pkt_view.py --quick data/powerg_burst_bytes_2025-06-06T13:34:44.353027.csv --key d17153ea74b95553d8b9fbb4cf876ca4 --nonce 258e6380399b5db86ce78158
...
quick: 0x0a -> 0x01/0xfd type 0x80, payload: 50a5d8
quick: 0x01 -> 0x0a/0xfd type 0x51, payload: 3400eb070500
quick: 0x0a -> 0x01/0xfd type 0x80, payload: 4f
quick: 0x01 -> 0x0a/0xfd type 0x51, payload: 330016190500
quick: 0x0a -> 0x01/0xfd type 0x80, payload: 4f
quick: 0x01 -> 0x0a/0xfd type 0x51, payload: 0f004b8d0500
quick: 0x01 -> 0x0a/0xfd type 0x52, payload: 140001000000070100
quick: 0x0a -> 0x01/0xfd type 0x50, payload: 1800
quick: 0x01 -> 0x0a/0xfd type 0x51, payload: 0f004b990500
quick: 0x01 -> 0x0a/0xfd type 0x52, payload: 140003000000070100
quick: 0x0a -> 0x01/0xfd type 0x50, payload: 1800
quick: 0x01 -> 0x0a/0xfd type 0x52, payload: 140004000000070100
quick: 0x0a -> 0x01/0xfd type 0x50, payload: 1900
quick: 0x01 -> 0x0a/0xfd type 0x51, payload: 0f0016a90500
...
```


## Estimate start time

(TODO: do this automatically)

Use the `--start-time` option with `pkt_view.py` to specify the starting network clock time, in order to help with packet decryption.

Look for first packet that shows correct network time, e.g. a type 0x51 packet from the main modem:

```
Packet on channel 15 (Burst center frequency: 914,693,228 Hz)
Start time: 19.129920204497626
CRC-16 (CC1101): 0x477b GOOD

...

RF message type: 0x51
Keystream head: dfea
Nonce/crypto mode: 3

...

types 0x51 / 0x71 first bytes
pkt info bit:   byte 0[7:7] =   0
RSSI-based value: 78
network topology: 0x00
modem timestamp: 170590311 (0xa2b0067)
```

Convert the start RF capture time from seconds to 32 KHz ticks, and subtract from the modem clock:

```
>>> ts = 170590311
>>> start_t =  19.129920204497626
>>> start_t_32khz = round((start_t) * 32768)
>>> start_t_32khz
626849
>>> (ts - start_t_32khz) & (2**32 - 1)
169963462
```
