# Calculate relative offset on a signed integer value.
# Point cursor to the offset integer value. Calculates address-relative offset from integer and its location in memory.
# @author James Chambers
# @category IAR

# Get data segment info
offset_data_addr = currentAddress

offset_val = getDataAt(offset_data_addr).getValue().getSignedValue()

print('Self-relative offset: %#x' % (offset_val))

calculated_addr = offset_data_addr.add(offset_val)

print('Calculated address: %s' % (calculated_addr))

setEOLComment(offset_data_addr, "addr-relative offset to %s" % (calculated_addr))
