import struct
from Crypto.Cipher import AES

"""
    http://www.ietf.org/rfc/rfc3394.txt
    quick'n'dirty AES wrap implementation
    used by iOS 4 KeyStore kernel extension for wrapping/unwrapping encryption keys
"""
def unpack64bit(s):
    return struct.unpack(">Q",s)[0]
def pack64bit(s):
    return struct.pack(">Q",s)

def AESUnwrap(kek, wrapped):
    C = []
    for i in xrange(len(wrapped)/8):
        C.append(unpack64bit(wrapped[i*8:i*8+8]))
    n = len(C) - 1
    R = [0] * (n+1)
    A = C[0]
    
    for i in xrange(1,n+1):
        R[i] = C[i]
    
    for j in reversed(xrange(0,6)):
        for i in reversed(xrange(1,n+1)):
            todec = pack64bit(A ^ (n*j+i))
            todec += pack64bit(R[i])
            B = AES.new(kek).decrypt(todec)
            A = unpack64bit(B[:8])
            R[i] = unpack64bit(B[8:])
    
    #assert A == 0xa6a6a6a6a6a6a6a6, "AESUnwrap: integrity check FAIL, wrong kek ?"
    if A != 0xa6a6a6a6a6a6a6a6:
        #print "AESUnwrap: integrity check FAIL, wrong kek ?"
        return None    
    res = "".join(map(pack64bit, R[1:]))
    return res

def AESwrap(kek, data):
    A = 0xa6a6a6a6a6a6a6a6
    R = [0]
    for i in xrange(len(data)/8):
        R.append(unpack64bit(data[i*8:i*8+8]))
    n = len(R) - 1
    
    for j in xrange(0,6):
        for i in xrange(1,n+1):
            B = AES.new(kek).encrypt(pack64bit(A) + pack64bit(R[i]))
            A = unpack64bit(B[:8]) ^ (n*j+i)
            R[i] = unpack64bit(B[8:])
    
    res = pack64bit(A) + "".join(map(pack64bit, R[1:]))
    return res

if __name__ == "__main__":
    #format (kek, data, expected_ciphertext)
    test_vectors = [
                    ("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
                    ("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
                    ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
                    ("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"),
                    ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"),
                    ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")                   
                    ]
    for kek, data, expected in test_vectors:
        ciphertext = AESwrap(kek.decode("hex"), data.decode("hex"))
        assert ciphertext == expected.decode("hex")
        assert AESUnwrap(kek.decode("hex"), ciphertext) == data.decode("hex")
    print "All tests OK !"
