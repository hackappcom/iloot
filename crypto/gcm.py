#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util import strxor
from struct import pack, unpack

def gcm_rightshift(vec):
    for x in range(15, 0, -1):
        c = vec[x] >> 1
        c |= (vec[x-1] << 7) & 0x80
        vec[x] = c
    vec[0] >>= 1
    return vec

def gcm_gf_mult(a, b):
    mask = [ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 ]
    poly = [ 0x00, 0xe1 ]

    Z = [0] * 16
    V = [c for c in a]

    for x in range(128):
        if b[x >> 3] & mask[x & 7]:
            Z = [V[y] ^ Z[y] for y in range(16)]
        bit = V[15] & 1
        V = gcm_rightshift(V)
        V[0] ^= poly[bit]
    return Z

def ghash(h, auth_data, data):
    u = (16 - len(data)) % 16
    v = (16 - len(auth_data)) % 16

    x = auth_data + chr(0) * v + data + chr(0) * u
    x += pack('>QQ', len(auth_data) * 8, len(data) * 8)

    y = [0] * 16
    vec_h = [ord(c) for c in h]

    for i in range(0, len(x), 16):
        block = [ord(c) for c in x[i:i+16]]
        y = [y[j] ^ block[j] for j in range(16)]
        y = gcm_gf_mult(y, vec_h)

    return ''.join(chr(c) for c in y)

def inc32(block):
    counter, = unpack('>L', block[12:])
    counter += 1
    return block[:12] + pack('>L', counter)

def gctr(k, icb, plaintext):
    y = ''
    if len(plaintext) == 0:
        return y

    aes = AES.new(k)
    cb = icb

    for i in range(0, len(plaintext), aes.block_size):
        cb = inc32(cb)
        encrypted = aes.encrypt(cb)
        plaintext_block = plaintext[i:i+aes.block_size]
        y += strxor.strxor(plaintext_block, encrypted[:len(plaintext_block)])

    return y

def gcm_decrypt(k, iv, encrypted, auth_data, tag):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    decrypted = gctr(k, y0, encrypted)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    if T != tag:
        raise ValueError('Decrypted data is invalid')
    else:
        return decrypted

def gcm_encrypt(k, iv, plaintext, auth_data):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    encrypted = gctr(k, y0, plaintext)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    return (encrypted, T)

def main():
    #http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
    k = 'AD7A2BD03EAC835A6F620FDCB506B345'.decode("hex")
    p = ''
    a = 'D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001'.decode("hex")
    iv = '12153524C0895E81B2C28465'.decode("hex")
    c, t = gcm_encrypt(k, iv, '', a)
    assert c == ""
    assert t == "f09478a9b09007d06f46e9b6a1da25dd".decode("hex")

    k = 'AD7A2BD03EAC835A6F620FDCB506B345'.decode("hex")
    p = '08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002'.decode("hex")
    a = 'D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81'.decode("hex")
    iv = '12153524C0895E81B2C28465'.decode("hex")
    c, t = gcm_encrypt(k, iv, p, a)
    assert c == '701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D'.decode("hex")
    assert t == '4F8D55E7D3F06FD5A13C0C29B9D5B880'.decode("hex")

    key = "91bfb6cbcff07b93a4c68bbfe99ac63b713f0627025c0fb1ffc5b0812dc284f8".decode("hex")
    data = "020000000B00000028000000DE44D22E96B1966BAEF4CBEA8675871D40BA669401BD4EBB52AF9C025134187E70549012058456BF0EC0FA1F8FF9F822AC4312AB2141FA712E6D1482358EAC1421A1BFFA81EF38BD0BF2E52675D665EFE3C534E188F575774FAA92E74345575E370B9982661FAE8BD9243B7AD7D2105B275424C0CA1145B9D43AFF04F2747E40D62EC60563960D62A894BE66F267B14D75C0572BE60CC9B339D440FCB418D4F729BBF15C14E0D3A43E4A8B44523D8B3B0F3E7DF85AA67A707EE19CB893277D2392234D7DBC17DA4A0BD7F166189FC54C16C20D287E20FD2FB11BD2CE09ADBDABB95124CD4BFE219E34D3C80E69570A5A506555D7094916C5D75E0065F1796F556EDF0DAA1AA758E0C85AE3951BD363F26B1D43F6CBAEE12D97AD3B60CFA89C1C76BB29F2B54BE31B6CE166F4860C5E5DA92588EF53AA946DF159E60E6F05009D12FB1E37".decode("hex")
    ciphertext = data[12+40:-16]
    tag = data[-16:]
    print repr(gcm_decrypt(key, '', ciphertext, '', tag))


if __name__ == '__main__':
    main()
