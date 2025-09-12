# decompress an IAR compressed data segment initializer
# Point cursor to the start of the words used by `iar_data_segment_initializer`
# (address-relative offset to the start of the compressed data)
# @author Sultan Qasim Khan & James Chambers
# @category IAR
import binascii

def iar_decompress(src):
    dst = bytearray(0x100000)
    src_addr = 0
    dst_addr = 0

    while src_addr < len(src):
        hdr = src[src_addr]
        uv1 = hdr & 0x03
        wsa = src_addr + 1
        if uv1 == 0:
            uv1 = src[wsa] + 3
            wsa += 1
        uv3 = hdr >> 4
        if uv3 == 0xF:
            uv3 = src[wsa] + 0xF
            wsa += 1

        # minus one seems strange
        for i in range(uv1 - 1):
            dst[dst_addr] = src[wsa]
            dst_addr += 1
            wsa += 1
        src_addr = wsa

        if uv3 != 0:
            lsb = src[wsa]
            msb = (hdr >> 2) & 0x03
            wsa += 1
            if msb == 3:
                msb = src[wsa]
                wsa += 1
            src_addr = wsa
            backtrack_count = lsb | (msb << 8)
            for i in range(uv3 + 2):
                dst[dst_addr] = dst[dst_addr - backtrack_count]
                dst_addr += 1

    return dst[:dst_addr]


# Get data segment info
info_start = currentAddress

compressed_data_offset = getDataAt(info_start).getValue().getSignedValue()
size_and_bit = getDataAt(info_start.add(4)).getValue().getValue()
data_seg_addr = getDataAt(info_start.add(8)).getValue()
compressed_size = size_and_bit >> 1

print('Self-relative offset to compressed data: %#x' % (compressed_data_offset))
print('Compressed data size and bit: %#x (size = %#x / %d)' % (size_and_bit, compressed_size, compressed_size))
print('Data segment address: %s' % (str(data_seg_addr)))

default_addr_space = getAddressFactory().getDefaultAddressSpace()

compressed_data = bytearray(getBytes(info_start.add(compressed_data_offset), compressed_size))

print('Compressed data:')
print(binascii.hexlify(compressed_data))

decompressed_data = iar_decompress(compressed_data)

print('Decompressed data (%#x bytes):' % (len(decompressed_data)))
print(binascii.hexlify(decompressed_data))
