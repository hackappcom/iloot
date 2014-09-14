from construct import RepeatUntil
from construct.core import Struct, Union
from construct.macros import *
from crypto.aes import AESdecryptCBC
from crypto.aeswrap import AESUnwrap
from zipfile import crc32
import struct

Dkey = 0x446B6579
EMF = 0x454D4621
BAG1 = 0x42414731
DONE = 0x444f4e45   #locker sentinel
#**** = 0x2A2A2A2A   #wildcard for erase

#MAGIC (kL) | LEN (2bytes) | TAG (4) | DATA (LEN)
Locker = Struct("Locker",
                String("magic",2),
                ULInt16("length"),
                Union("tag",
                      ULInt32("int"),
                      String("tag",4))
                ,
                String("data", lambda ctx: ctx["length"])
                )

Lockers = RepeatUntil(lambda obj, ctx: obj.tag.int == DONE, Locker)

def xor_strings(s, key):
        res = ""
        for i in xrange(len(s)):
                res += chr(ord(s[i]) ^ ord(key[i%len(key)]))
        return res

def check_effaceable_header(plog):
    z = xor_strings(plog[:16], plog[16:32])
    if z[:4] != "ecaF":
        return False
    plog_generation = struct.unpack("<L", plog[0x38:0x3C])[0]
    print "Effaceable generation" , plog_generation
    plog_crc = crc32(plog[0x40:0x40 + 960], crc32(plog[0x20:0x3C], crc32(z))) & 0xffffffff
    assert plog_crc == struct.unpack("<L", plog[0x3C:0x40])[0] , "Effaceable CRC"
    print "Effaceable CRC OK"
    return True

class EffaceableLockers(object):
    def __init__(self, data):
        self.lockers = {}
        for l in Lockers.parse(data):
            tag = l.tag.int & ~0x80000000
            tag = struct.pack("<L", tag)[::-1]
            self.lockers[tag] = l.data
    
    def display(self):
        print "Lockers : " + ", ".join(sorted(self.lockers.keys()))

    def get(self, tag):
        return self.lockers.get(tag)
    
    def get_DKey(self, k835):
        if self.lockers.has_key("Dkey"):        
            return AESUnwrap(k835, self.lockers["Dkey"])

    def get_EMF(self, k89b):
        if self.lockers.has_key("LwVM"):
            lwvm = AESdecryptCBC(self.lockers["LwVM"], k89b)
            return lwvm[-32:]
        elif self.lockers.has_key("EMF!"):
            return AESdecryptCBC(self.lockers["EMF!"][4:], k89b)
            