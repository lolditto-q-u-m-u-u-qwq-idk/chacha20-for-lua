local string_byte = string.byte
local string_char = string.char
local string_sub  = string.sub
local table_concat = table.concat
local bit_band    = bit32.band
local bit_bxor    = bit32.bxor
local bit_lshift  = bit32.lshift
local bit_bor = bit32.bor
local bit_rshift  = bit32.rshift
local bit_lrotate = bit32.lrotate
local u32 = function(x)
 return bit_band(x, 0xFFFFFFFF)--take the lower 32 bits of x.
end
local quarter_round = function(st, a, b, c, d)--the quarter-round of chacha20, uses ARX to update four states
    st[a] = u32(st[a] + st[b])
    st[d] = bit_lrotate(bit_bxor(st[d], st[a]), 16)
    st[c] = u32(st[c] + st[d])
    st[b] = bit_lrotate(bit_bxor(st[b], st[c]), 12)
    st[a] = u32(st[a] + st[b])
    st[d] = bit_lrotate(bit_bxor(st[d], st[a]), 8)
    st[c] = u32(st[c] + st[d])
    st[b] = bit_lrotate(bit_bxor(st[b], st[c]), 7)
end
local le_bytes_to_u32 = function(str, offset)--read the specified 4 bytes in little-endian format from the string, and then combine them into a 32-bit number
    offset = offset or 1
    return bit_bor(
        string_byte(str, offset),
        bit_lshift(string_byte(str, offset + 1), 8),
        bit_lshift(string_byte(str, offset + 2), 16),
        bit_lshift(string_byte(str, offset + 3), 24)
    )
end
local u32_to_le_bytes = function(w)--split a 32-bit number into a 4-byte little-endian string
    return string_char(
        bit_band(w, 0xFF),
        bit_band(bit_rshift(w, 8), 0xFF),
        bit_band(bit_rshift(w, 16), 0xFF),
        bit_band(bit_rshift(w, 24), 0xFF)
    )
end
local chacha20_block = function(key, nonce, counter)--generate a 64-byte keystream block from key, nonce and counter
    local st = {}--initialize 16 32-bit status words
    st[1] = 0x61707865
    st[2] = 0x3320646e
    st[3] = 0x79622d32
    st[4] = 0x6b206574--the constant
    for i = 0, 7 do st[5 + i] = le_bytes_to_u32(key, 1 + i * 4) end--load 32-byte key as eight 32-bit little-endian words into status words
    st[13] = counter--load the counter into status words
    st[14] = le_bytes_to_u32(nonce, 1)--load nonce as three 32-bit little-endian words into status words
    st[15] = le_bytes_to_u32(nonce, 5)
    st[16] = le_bytes_to_u32(nonce, 9)
    local orig = {}
    for i = 1, 16 do orig[i] = st[i] end--save the status words (not the reference)
    for _ = 1, 10 do--10 double-row rotations
        quarter_round(st, 1, 5, 9, 13)
        quarter_round(st, 2, 6, 10, 14)
        quarter_round(st, 3, 7, 11, 15)
        quarter_round(st, 4, 8, 12, 16)
        quarter_round(st, 1, 6, 11, 16)
        quarter_round(st, 2, 7, 12, 13)
        quarter_round(st, 3, 8, 9, 14)
        quarter_round(st, 4, 5, 10, 15)
    end
    for i = 1, 16 do st[i] = u32(st[i] + orig[i]) end--add the new state to the old state
    local out = {}
    for i = 1, 16 do out[i] = u32_to_le_bytes(st[i]) end--serialize 16 32-bit words to little-endian 4-byte string
    return table_concat(out)
end
local xor_bytes = function(a, b, len)--XOR the first len bytes of strings a and b
    local t = {}
    for i = 1, len do
        t[i] = string_char(bit_bxor(string_byte(a, i), string_byte(b, i)))
    end
    return table_concat(t)
end
local chacha20 = function(key, nonce, counter, plaintext)--main function
    local pt_len = #plaintext
    local ct = {}
    local pos = 1
    while pos <= pt_len do
        local block = chacha20_block(key, nonce, counter)
        local take = (64 < (pt_len - pos + 1)) and 64 or (pt_len - pos + 1)
        ct[#ct + 1] = xor_bytes(string_sub(plaintext, pos, pos + take - 1), string_sub(block, 1, take), take)
        pos = pos + take
        counter = counter + 1
    end
    return table_concat(ct)
end
