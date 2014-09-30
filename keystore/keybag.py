from crypto.PBKDF2 import PBKDF2
from crypto.aes import AESdecryptCBC
from crypto.aeswrap import AESUnwrap
from crypto.aeswrap import AESwrap
from crypto.curve25519 import curve25519
from hashlib import sha256, sha1
from util.bplist import BPlistReader
from util.tlv import loopTLVBlocks, tlvToDict
import hmac
import struct

KEYBAG_TAGS = ["VERS", "TYPE", "UUID", "HMCK", "WRAP", "SALT", "ITER"]
CLASSKEY_TAGS = ["CLAS","WRAP","WPKY", "KTYP", "PBKY"]  #UUID
KEYBAG_TYPES = ["System", "Backup", "Escrow", "OTA (icloud)"]
SYSTEM_KEYBAG = 0
BACKUP_KEYBAG = 1
ESCROW_KEYBAG = 2
OTA_KEYBAG = 3

#ORed flags in TYPE since iOS 5
FLAG_UIDPLUS = 0x40000000   # UIDPlus hardware key (>= iPad 3)
FLAG_UNKNOWN = 0x80000000

WRAP_DEVICE = 1
WRAP_PASSCODE = 2

KEY_TYPES = ["AES", "Curve25519"]
PROTECTION_CLASSES={
    1:"NSFileProtectionComplete",
    2:"NSFileProtectionCompleteUnlessOpen",
    3:"NSFileProtectionCompleteUntilFirstUserAuthentication",
    4:"NSFileProtectionNone",
    5:"NSFileProtectionRecovery?",

    6: "kSecAttrAccessibleWhenUnlocked",
    7: "kSecAttrAccessibleAfterFirstUnlock",
    8: "kSecAttrAccessibleAlways",
    9: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    10: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    11: "kSecAttrAccessibleAlwaysThisDeviceOnly"
}

"""
    device key : key 0x835
"""
class Keybag(object):
    def __init__(self, data):
        self.type = None
        self.uuid = None
        self.wrap = None
        self.deviceKey = None
        self.unlocked = False
        self.passcodeComplexity = 0
        self.attrs = {}
        self.classKeys = {}
        self.KeyBagKeys = None #DATASIGN blob
        self.parseBinaryBlob(data)

    @staticmethod
    def getSystemkbfileWipeID(filename):
        mkb = BPlistReader.plistWithFile(filename)
        return mkb["_MKBWIPEID"]

    @staticmethod
    def createWithPlist(pldict):
        k835 = pldict.key835.decode("hex")
        data = ""
        if pldict.has_key("KeyBagKeys"):
            data = pldict["KeyBagKeys"].data
        else:
            data = ""
        keybag = Keybag.createWithDataSignBlob(data, k835)

        if pldict.has_key("passcodeKey"):
            if keybag.unlockWithPasscodeKey(pldict["passcodeKey"].decode("hex")):
                print "Keybag unlocked with passcode key"
            else:
                print "FAILed to unlock keybag with passcode key"
        #HAX: inject DKey
        keybag.setDKey(pldict)
        return keybag

    def setDKey(self, device_infos):
        self.classKeys[4] = {"CLAS": 4, "KEY": device_infos["DKey"].decode("hex")}

    @staticmethod
    def createWithSystemkbfile(filename, bag1key, deviceKey=None):
        if filename.startswith("bplist"): #HAX
            mkb = BPlistReader.plistWithString(filename)
        else:
            mkb = BPlistReader.plistWithFile(filename)
        try:
            decryptedPlist  = AESdecryptCBC(mkb["_MKBPAYLOAD"].data, bag1key, mkb["_MKBIV"].data, padding=True)
        except:
            print "FAIL: AESdecryptCBC _MKBPAYLOAD => wrong BAG1 key ?"
            return None
        if not decryptedPlist.startswith("bplist"):
            print "FAIL: decrypted _MKBPAYLOAD is not bplist"
            return None
        decryptedPlist = BPlistReader.plistWithString(decryptedPlist)
        blob = decryptedPlist["KeyBagKeys"].data
        kb = Keybag.createWithDataSignBlob(blob, deviceKey)
        if decryptedPlist.has_key("OpaqueStuff"):
            OpaqueStuff = BPlistReader.plistWithString(decryptedPlist["OpaqueStuff"].data)
            kb.passcodeComplexity = OpaqueStuff.get("keyboardType")
        return kb


    @staticmethod
    def createWithDataSignBlob(blob, deviceKey=None):
        keybag = tlvToDict(blob)

        kb = Keybag(keybag.get("DATA", ""))
        kb.deviceKey = deviceKey
        kb.KeyBagKeys = blob
        kb.unlockAlwaysAccessible()

        if len(keybag.get("SIGN", "")):
            hmackey = AESUnwrap(deviceKey, kb.attrs["HMCK"])
            #hmac key and data are swapped (on purpose or by mistake ?)
            sigcheck = hmac.new(key=keybag["DATA"], msg=hmackey, digestmod=sha1).digest()
            #fixed in ios 7
            if kb.attrs["VERS"] >= 4:
                sigcheck = hmac.new(key=hmackey, msg=keybag["DATA"], digestmod=sha1).digest()
            if sigcheck != keybag.get("SIGN", ""):
                print "Keybag: SIGN check FAIL"
        return kb

    @staticmethod
    def createWithBackupManifest(manifest, password, deviceKey=None):
        kb = Keybag(manifest["BackupKeyBag"].data)
        kb.deviceKey = deviceKey
        if not kb.unlockBackupKeybagWithPasscode(password):
            print "Cannot decrypt backup keybag. Wrong password ?"
            return
        return kb

    def isBackupKeybag(self):
        return self.type == BACKUP_KEYBAG

    def parseBinaryBlob(self, data):
        currentClassKey = None

        for tag, data in loopTLVBlocks(data):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == "TYPE":
                self.type = data & 0x3FFFFFFF #ignore the flags
                if self.type > 3:
                    print "FAIL: keybag type > 3 : %d" % self.type
            elif tag == "UUID" and self.uuid is None:
                self.uuid = data
            elif tag == "WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == "UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey["CLAS"] & 0xF] = currentClassKey
                currentClassKey = {"UUID": data}
            elif tag in CLASSKEY_TAGS:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey["CLAS"] & 0xF] = currentClassKey

    def getPasscodekeyFromPasscode(self, passcode):
        if self.type == BACKUP_KEYBAG or self.type == OTA_KEYBAG:
            return PBKDF2(passcode, self.attrs["SALT"], iterations=self.attrs["ITER"]).read(32)
        else:
            #Warning, need to run derivation on device with this result
            return PBKDF2(passcode, self.attrs["SALT"], iterations=1).read(32)

    def unlockBackupKeybagWithPasscode(self, passcode):
        if self.type != BACKUP_KEYBAG and self.type != OTA_KEYBAG:
            print "unlockBackupKeybagWithPasscode: not a backup keybag"
            return False
        return self.unlockWithPasscodeKey(self.getPasscodekeyFromPasscode(passcode))

    def unlockAlwaysAccessible(self):
        for classkey in self.classKeys.values():
            k = classkey["WPKY"]
            if classkey["WRAP"] ==  WRAP_DEVICE:
                if not self.deviceKey:
                    continue
                k = AESdecryptCBC(k, self.deviceKey)
                classkey["KEY"] = k
        return True

    def unlockWithPasscodeKey(self, passcodekey):
        if self.type != BACKUP_KEYBAG and self.type != OTA_KEYBAG:
            if not self.deviceKey:
                print "ERROR, need device key to unlock keybag"
                return False

        for classkey in self.classKeys.values():
            if not classkey.has_key("WPKY"):
                continue
            k = classkey["WPKY"]
            if classkey["WRAP"] & WRAP_PASSCODE:
                k = AESUnwrap(passcodekey, classkey["WPKY"])
                if not k:
                    return False
            if classkey["WRAP"] & WRAP_DEVICE:
                if not self.deviceKey:
                    continue
                k = AESdecryptCBC(k, self.deviceKey)
            classkey["KEY"] = k
        self.unlocked =  True
        return True

    def unwrapCurve25519(self, persistent_class, persistent_key):
        assert len(persistent_key) == 0x48
        #assert persistent_class == 2    #NSFileProtectionCompleteUnlessOpen
        mysecret = self.classKeys[persistent_class]["KEY"]
        mypublic = self.classKeys[persistent_class]["PBKY"]
        hispublic = persistent_key[:32]
        shared = curve25519(mysecret, hispublic)
        md = sha256('\x00\x00\x00\x01' + shared + hispublic + mypublic).digest()
        return AESUnwrap(md, persistent_key[32:])

    def unwrapKeyForClass(self, clas, persistent_key, printError=True):
        if not self.classKeys.has_key(clas) or not self.classKeys[clas].has_key("KEY"):
            if printError: print "Keybag key %d missing or locked" % clas
            return ""
        ck = self.classKeys[clas]["KEY"]
        #if self.attrs.get("VERS", 2) >= 3 and clas == 2:
        if self.attrs.get("VERS", 2) >= 3 and self.classKeys[clas].get("KTYP", 0) == 1:
            return self.unwrapCurve25519(clas, persistent_key)
        if len(persistent_key) == 0x28:
            return AESUnwrap(ck, persistent_key)
        return

    def wrapKeyForClass(self, clas, persistent_key):
        if not self.classKeys.has_key(clas) or not self.classKeys[clas].has_key("KEY"):
            print "Keybag key %d missing or locked" % clas
            return ""
        ck = self.classKeys[clas]["KEY"]
        return AESwrap(ck, persistent_key)

    def printClassKeys(self):
        print "Keybag type : %s keybag (%d)" % (KEYBAG_TYPES[self.type], self.type)
        print "Keybag version : %d" % self.attrs["VERS"]
        print "Keybag UUID : %s" % self.uuid.encode("hex")
        print "-"*128
        print "".join(["Class".ljust(53),
                      "WRAP".ljust(5),
                      "Type".ljust(11),
                      "Key".ljust(65),
                      "Public key"])
        print "-"*128
        for k, ck in self.classKeys.items():
            if k == 6: print ""
            print "".join([PROTECTION_CLASSES.get(k, "%d" % k).ljust(53),
                                          str(ck.get("WRAP","")).ljust(5),
                                          KEY_TYPES[ck.get("KTYP",0)].ljust(11),
                                          ck.get("KEY", "").encode("hex").ljust(65),
                                          ck.get("PBKY", "").encode("hex")])
        print ""

    def getClearClassKeysDict(self):
        if self.unlocked:
            d = {}
            for ck in self.classKeys.values():
                d["%d" % (ck["CLAS"] & 0xF)] = ck.get("KEY","").encode("hex")
            return d
