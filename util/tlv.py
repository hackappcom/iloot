import struct

def tlvToDict(blob):
    d = {}
    for tag,data in loopTLVBlocks(blob):
        d[tag] = data
    return d

def tlvToList(blob):
    return list(loopTLVBlocks(blob))
    
def loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i+4]
        length = struct.unpack(">L",blob[i+4:i+8])[0]
        data = blob[i+8:i+8+length]
        yield (tag,data)
        i += 8 + length