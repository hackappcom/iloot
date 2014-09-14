from ctypes import *
import sys

if sys.platform == "darwin":
    kCCOptionECBMode=2
    kCCAlgorithmAES128=0
    kCCEncrypt=0
    kCCDecrypt=1

    Security = cdll.LoadLibrary("/System/Library/Frameworks/Security.framework/Security")
    #http://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html
    #CCCryptorStatus
    # CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
    #     const void *key, size_t keyLength, const void *iv,
    #     const void *dataIn, size_t dataInLength, void *dataOut,
    #     size_t dataOutAvailable, size_t *dataOutMoved);
    Security.CCCrypt.argtypes = [c_uint, c_uint, c_uint, c_void_p,
                                c_size_t, c_void_p, c_void_p,
                                c_size_t, c_void_p, c_size_t, c_void_p]
    class AES(object):
        def __init__(self, key, iv=None):
            self.key = key
            self.iv = None
            if iv:
                self.iv = create_string_buffer(iv)
            self.options = (self.iv == None) * kCCOptionECBMode

        def __del__(self):
            pass

        def cccrypt(self, op, data):
            iv = None
            keyb = create_string_buffer(self.key)
            clear = create_string_buffer(data)
            out = create_string_buffer("\x00" * len(data))
            sizeout = c_ulonglong()
            r = Security.CCCrypt(op, kCCAlgorithmAES128, self.options, keyb, len(self.key), self.iv, clear, len(data), out, len(data), byref(sizeout))
            return out.raw[:-1]

        def encrypt(self, data):
            return self.cccrypt(kCCEncrypt, data)

        def decrypt(self, data):
            return self.cccrypt(kCCDecrypt, data)

elif sys.platform == "win32":
    PROV_RSA_AES = 24
    CRYPT_VERIFYCONTEXT = 0xF0000000
    PLAINTEXTKEYBLOB = 8
    CUR_BLOB_VERSION = 2
    KP_IV = 1
    KP_MODE = 4
    CRYPT_MODE_CBC = 1
    ALG_CLASS_DATA_ENCRYPT  = (3 << 13)
    ALG_TYPE_BLOCK          = (3 << 9)
    ALG_SID_AES_128 = 14
    ALG_SID_AES_192 = 15
    ALG_SID_AES_256 = 16
    CALG_AES_128    = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128)
    CALG_AES_192    = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192)
    CALG_AES_256    = (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256)

    CryptAcquireContext = windll.Advapi32.CryptAcquireContextA
    CryptReleaseContext = windll.Advapi32.CryptReleaseContext
    CryptImportKey = windll.Advapi32.CryptImportKey
    CryptSetKeyParam = windll.Advapi32.CryptSetKeyParam
    CryptDestroyKey = windll.Advapi32.CryptDestroyKey
    CryptEncrypt = windll.Advapi32.CryptEncrypt
    CryptDecrypt = windll.Advapi32.CryptDecrypt

    class AESBlob(Structure):
        _fields_ = [("bType", c_byte),
                    ("bVersion", c_byte),
                    ("reserved", c_short),
                    ("aiKeyAlg", c_uint),
                    ("keyLength", c_uint),
                    ("key", c_byte * 32)
                    ]

    class AES(object):
        def __init__(self, key, iv=None):
            self.hProvider = c_void_p()
            self.hKey = c_void_p()

            if iv and len(iv) != 16:
                print "Bad IV length %d" % len(iv)
                return

            blob = AESBlob()
            blob.bType = PLAINTEXTKEYBLOB
            blob.bVersion = CUR_BLOB_VERSION
            blob.reserved = 0
            if len(key) == 16:        blob.aiKeyAlg = CALG_AES_128
            elif len(key) == 24:      blob.aiKeyAlg = CALG_AES_192
            elif len(key) == 32:      blob.aiKeyAlg = CALG_AES_256
            else:
                print "bad key size"
                return

            if CryptAcquireContext(byref(self.hProvider), 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == 0:
                print "CryptAcquireContext failed"
                return

            blob.keyLength = len(key)
            for i in xrange(len(key)):
                blob.key[i] = ord(key[i])

            if CryptImportKey(self.hProvider, byref(blob), sizeof(blob), 0, 0, byref(self.hKey)) == 0:
                print "CryptImportKey failed"
                CryptReleaseContext(self.hProvider, 0)
                return

            if iv:
                if CryptSetKeyParam(self.hKey, KP_IV, create_string_buffer(iv), 0 ) == 0:
                    print "CryptSetKeyParam KP_MODE failed"

                dwMode = c_uint(CRYPT_MODE_CBC)
                if CryptSetKeyParam(self.hKey, KP_MODE, byref(dwMode), 0 ) == 0:
                    print "CryptSetKeyParam KP_MODE failed"

        def __del__(self):
            CryptDestroyKey(self.hKey)
            CryptReleaseContext(self.hProvider, 0)

        def encrypt(self, data):
            pad = ""
            #dwBufLen must be at least 32 for AES with padding
            #if len(data) < 32:
            #    pad = "\x00" * (32- len(data))
            buf = create_string_buffer(data + pad)
            l = c_uint(len(data))
            if CryptEncrypt(self.hKey, 0, False, 0, buf, byref(l), len(buf)) == 0:
                print "CryptEncrypt failed"
                return
            return buf.raw[:len(data)]

        def decrypt(self, data):
            buf = create_string_buffer(data)
            l = c_uint(len(data))
            if CryptDecrypt(self.hKey, 0, False, 0, buf, byref(l)) == 0:
                print "CryptDecrypt failed"
                return
            return buf.raw[:-1]

#replicate pycrypto interface
MODE_ECB = 1
MODE_CBC = 2
def new(k,m,iv):
    return AES(k,iv)

if __name__ == "__main__":
    tests = [("2b7e151628aed2a6abf7158809cf4f3c","6bc1bee22e409f96e93d7e117393172a","3ad77bb40d7a3660a89ecaf32466ef97"),
    ("2b7e151628aed2a6abf7158809cf4f3c","ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
    ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b","6bc1bee22e409f96e93d7e117393172a","bd334f1d6e45f25ff712a214571fa5cc"),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4","6bc1bee22e409f96e93d7e117393172a","f3eed1bdb5d2a03c064b5a7e3db181f8")
    ]
    print "Platform: %s" % sys.platform
    print "AES test vectors"

    for k,clear,ciph in tests:
        assert AES(k.decode("hex")).encrypt(clear.decode("hex")) == ciph.decode("hex")
        assert AES(k.decode("hex")).decrypt(ciph.decode("hex")) == clear.decode("hex")
    print "All tests OK !"
