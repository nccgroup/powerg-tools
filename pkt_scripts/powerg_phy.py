PREAMBLE = b'\xaa\xaa\xaa\xaa'
SYNC_WORD = b'\x1f\x35\x1f\x35'

# PowerG 915 MHz values
BOTTOM_FREQ = 912749725
CHAN_SPACING = 129730
NUM_CHANNELS = 50
CHANNELS = [BOTTOM_FREQ + chan_id * CHAN_SPACING for chan_id in range(NUM_CHANNELS)]
OVERALL_CENTER_FREQ = BOTTOM_FREQ + (CHAN_SPACING * (NUM_CHANNELS-1)) / 2


def channel_index(freq):
    """Return zero-based channel index for burst center frequency"""
    return round((freq - BOTTOM_FREQ) / CHAN_SPACING)
