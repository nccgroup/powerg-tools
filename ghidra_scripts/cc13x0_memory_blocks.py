# create memory blocks for CC13x0
# @author James Chambers
# @category TI

from ghidra.app.cmd.memory import (AddUninitializedMemoryBlockCmd, AddBitMappedMemoryBlockCmd)


addr_space = getAddressFactory().getDefaultAddressSpace()


mem_block_cmds = [
    AddUninitializedMemoryBlockCmd(
        "BROM",
        "", "",
        addr_space.getAddress(0x10000000), 0x1cc00,
        True, True, True, False, False),

    AddUninitializedMemoryBlockCmd(
        "GPRAM",
        "", "",
        addr_space.getAddress(0x11000000), 0x2000,
        True, True, True, False, False),

    # SRAM

    AddUninitializedMemoryBlockCmd(
        "RFC_RAM",
        "", "",
        addr_space.getAddress(0x21000000), 0x1000000,
        True, True, True, False, False),

    AddBitMappedMemoryBlockCmd(
        "sram_bitband",
        "Incorrect mapping, Ghidra doesn't support mapping 1 bit to 4 bytes", "",
        addr_space.getAddress(0x22000000), 0x2000000,
        True, True, False, False, addr_space.getAddress(0x20000000), False),

    AddBitMappedMemoryBlockCmd(
        "peripherals_bitband",
        "Incorrect mapping, Ghidra doesn't support mapping 1 bit to 4 bytes", "",
        addr_space.getAddress(0x42000000), 0x2000000,
        True, True, False, False, addr_space.getAddress(0x40000000), False),

]

memory = currentProgram.getMemory()

for cmd in mem_block_cmds:
    try:
        cmd.applyTo(currentProgram)
    except Exception as e:
        print(e)

print("Remember to get peripheral memory blocks with SVD-Loader")
