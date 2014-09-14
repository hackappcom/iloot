from Crypto.Util import number

CURVE_P = (2**255 - 19)
CURVE_A = 121665

def curve25519_monty(x1, z1, x2, z2, qmqp):
    a = (x1 + z1) * (x2 - z2) % CURVE_P
    b = (x1 - z1) * (x2 + z2) % CURVE_P
    x4 = (a + b) * (a + b) % CURVE_P

    e = (a - b) * (a - b) % CURVE_P
    z4 = e * qmqp % CURVE_P

    a = (x1 + z1) * (x1 + z1) % CURVE_P
    b = (x1 - z1) * (x1 - z1) % CURVE_P
    x3 = a * b % CURVE_P

    g = (a - b) % CURVE_P
    h = (a + CURVE_A * g) % CURVE_P
    z3 = (g * h) % CURVE_P

    return x3, z3, x4, z4

def curve25519_mult(n, q):
    nqpqx, nqpqz = q, 1
    nqx, nqz = 1, 0

    for i in range(255, -1, -1):
        if (n >> i) & 1:
            nqpqx,nqpqz,nqx,nqz = curve25519_monty(nqpqx, nqpqz, nqx, nqz, q)
        else:
            nqx,nqz,nqpqx,nqpqz = curve25519_monty(nqx, nqz, nqpqx, nqpqz, q)
    return nqx, nqz

def curve25519(secret, basepoint):
    a = ord(secret[0])
    a &= 248
    b = ord(secret[31])
    b &= 127
    b |= 64
    s = chr(a) + secret[1:-1] + chr(b)

    s = number.bytes_to_long(s[::-1])
    basepoint = number.bytes_to_long(basepoint[::-1])

    x, z = curve25519_mult(s, basepoint)
    zmone = number.inverse(z, CURVE_P)
    z = x * zmone % CURVE_P
    return number.long_to_bytes(z)[::-1]


if __name__ == "__main__":
    from crypto.aeswrap import AESUnwrap
    from Crypto.Hash import SHA256

    z="04000000080000000200000048000000000000000000000000000000000000000000000002917dc2542198edeb1078c4d1ebab74d9ca87890657ba02b9825dadf20a002f44360c6f87743fac0236df1f9eedbea801e31677aef3a09adfb4e10a37ae27facf419ab3ea3f39f4".decode("hex")

    mysecret = "99b66345829d8c05041eea1ba1ed5b2984c3e5ec7a756ef053473c7f22b49f14".decode("hex")
    mypublic = "b1c652786697a5feef36a56f36fde524a21193f4e563627977ab515f600fdb3a".decode("hex")
    hispublic = z[36:36+32]

    #c4d9fe462a2ebbf0745195ce7dc5e8b49947bbd5b42da74175d5f8125b44582b
    shared = curve25519(mysecret, hispublic)
    print shared.encode("hex")
    
    h = SHA256.new()
    h.update('\x00\x00\x00\x01')
    h.update(shared)
    h.update(hispublic)
    h.update(mypublic)
    md = h.digest()

    #e442c81b91ea876d3cf42d3aea75f4b0c3f90f9fd045e1f5784b91260f3bdc9c
    print AESUnwrap(md, z[32+36:]).encode("hex")
