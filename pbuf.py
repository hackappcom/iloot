def decode_protobuf_array(data, obj_class):
    n = len(data)
    i = 0
    res = []
    while i < n:
        (length, i) = _DecodeVarint(data, i)
        l3 = obj_class()
        l3.ParseFromString(data[i:i+length])
        res.append(l3)
        i += length
    return res

def encode_protobuf_array(res):
    z = ""
    for o in res:
        d = o.SerializeToString()
        z += _EncodeVarint(len(d))
        z += d
    return z

#decoder.py
def _VarintDecoder(mask):
    local_ord = ord
    def DecodeVarint(buffer, pos):
        result = 0
        shift = 0
        while 1:
            b = local_ord(buffer[pos])
            result |= ((b & 0x7f) << shift)
            pos += 1
            if not (b & 0x80):
                result &= mask
                return (result, pos)
            shift += 7
            if shift >= 64:
                raise _DecodeError('Too many bytes when decoding varint.')
    return DecodeVarint

_DecodeVarint = _VarintDecoder((1 << 64) - 1)


def _VarintEncoder():
    """Return an encoder for a basic varint value (does not include tag)."""
    
    local_chr = chr
    def EncodeVarint( value):
        bits = value & 0x7f
        value >>= 7
        z=""
        while value:
            z += local_chr(0x80|bits)
            bits = value & 0x7f
            value >>= 7
        return z + local_chr(bits)
    
    return EncodeVarint

_EncodeVarint = _VarintEncoder()
