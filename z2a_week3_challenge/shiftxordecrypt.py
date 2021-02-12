

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

hex_string='DA1B1B5B6BFFAEAE5B4A6B1B0A7ACABA'
byte_arr = bytearray.fromhex(hex_string)
out_byte_arr = bytearray(len(byte_arr))
for byte1 in byte_arr:
    inverted_byte = rol(byte1, 4, 16)
    print(hex(inverted_byte))
    out_byte_arr.append(inverted_byte)
#print(hex(out_byte_arr))
