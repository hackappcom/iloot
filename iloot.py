import base64
from datetime import datetime
import getpass
import hashlib
from httplib import HTTPSConnection
import os
import plistlib
from pprint import pprint
import re
import struct
import sys


from chunkserver_pb2 import FileGroups
from crypto.aes import AESencryptCBC, AESdecryptCBC, AESdecryptCFB
from icloud_pb2 import MBSAccount, MBSBackup, MBSKeySet, MBSFile, MBSFileAuthToken, MBSFileAuthTokens
from keystore.keybag import Keybag
from pbuf import decode_protobuf_array, encode_protobuf_array
from util import hexdump, makedirs

Client_Info = "<iPhone2,1> <iPhone OS;5.1.1;9B206> <com.apple.AppleAccount/1.0 ((null)/(null))>"
USER_AGENT_UBD = "ubd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
USER_AGENT_MOBILE_BACKUP = "MobileBackup/5.1.1 (9B206; iPhone3,1)"
USER_AGENT_BACKUPD = "backupd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
Client_Info_backup = "<N88AP> <iPhone OS;5.1.1;9B206> <com.apple.icloud.content/211.1 (com.apple.MobileBackup/9B206)>"

#XXX handle all signature types
def chunk_signature(data):
    h = hashlib.sha256(data).digest()
    return hashlib.sha256(h).digest()[:20]

def decrypt_chunk(data, chunk_encryption_key, chunk_checksum):
    clear = AESdecryptCFB(data, chunk_encryption_key[1:])
    if chunk_checksum[1:] == chunk_signature(clear):
        return clear
    print "chunk decryption Failed"
    return None

def plist_request(host, method, url, body, headers):
    h = HTTPSConnection(host)
    r = h.request(method, url, body, headers)
    res = h.getresponse()
    if res.status != 200:
        print "Request %s returned code %d" % (url, res.status)
        return
    return plistlib.readPlistFromString(res.read())

def probobuf_request(host, method, url, body, headers, msg=None):
    h = HTTPSConnection(host)
    r = h.request(method, url, body, headers)
    res = h.getresponse()
    length = res.getheader("content-length")
    if length == None: length = 0
    else: length = int(length)
    data = res.read()
    while len(data) < length:
        d = res.read()
        data += d
    h.close()
    if msg == None:
        return data
    res = msg()
    res.ParseFromString(data)
    return res


def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

class MobileBackupClient(object):
    def __init__(self, account_settings, dsPrsID, auth, outputFolder):
        mobilebackup_url = account_settings["com.apple.mobileme"]["com.apple.Dataclass.Backup"]["url"]
        content_url = account_settings["com.apple.mobileme"]["com.apple.Dataclass.Content"]["url"]

        self.mobilebackup_host = re.match("https://(.*):443", mobilebackup_url).group(1)
        self.content_host = re.match("https://(.*):443", content_url).group(1)
        self.dsPrsID = dsPrsID
        self.headers = {"Authorization": auth,
                        "X-MMe-Client-Info": Client_Info,
                        "User-Agent": USER_AGENT_MOBILE_BACKUP,
                        "X-Apple-MBS-Protocol-Version": "1.7"
        }
        self.headers2 = {"x-apple-mmcs-proto-version": "3.3",
            "x-apple-mmcs-dataclass": "com.apple.Dataclass.Backup",
            "x-apple-mme-dsid": str(self.dsPrsID),
            "User-Agent":USER_AGENT_BACKUPD,
            "Accept": "application/vnd.com.apple.me.ubchunk+protobuf",
            "Content-Type": "application/vnd.com.apple.me.ubchunk+protobuf",
            "x-mme-client-info": Client_Info_backup
        }
        self.files = {}
        self.outputFolder = outputFolder

    def mobileBackupRequest(self, method, url, msg=None, body=""):
        return probobuf_request(self.mobilebackup_host, method, url, body, self.headers, msg)

    def getAccount(self):
        return self.mobileBackupRequest("GET", "/mbs/%d" % self.dsPrsID, MBSAccount)

    def getBackup(self, backupUDID):
        return self.mobileBackupRequest("GET", "/mbs/%d/%s" % (self.dsPrsID, backupUDID.encode("hex")), MBSBackup)

    def getKeys(self, backupUDID):
        return self.mobileBackupRequest("GET", "/mbs/%d/%s/getKeys" % (self.dsPrsID, backupUDID.encode("hex")), MBSKeySet)

    def listFiles(self, backupUDID, snapshotId):
        files = self.mobileBackupRequest("GET", "/mbs/%d/%s/%d/listFiles?offset=0&limit=100" % (self.dsPrsID, backupUDID.encode("hex"), snapshotId))
        i = 100
        files2 = 1
        while files2:


            files2 = self.mobileBackupRequest("GET", "/mbs/%d/%s/%d/listFiles?offset=%s&limit=100" % (self.dsPrsID, backupUDID.encode("hex"), snapshotId,str(i)))
            if files2:
                i = i + 100
                files = files + files2
                print "\tShifting offset: ", i

        #print files

        return decode_protobuf_array(files, MBSFile)

    def getFiles(self, backupUDID, snapshotId, files):
        r = []
        h = {}
        for f in files:
            if f.Size == 0:
                continue
            ff = MBSFile()
            ff.FileID = f.FileID
            h[f.FileID] = f.Signature
            r.append(ff)
            self.files[f.Signature] = f
        body = encode_protobuf_array(r)
        z = self.mobileBackupRequest("POST", "/mbs/%d/%s/%d/getFiles" % (self.dsPrsID, backupUDID.encode("hex"), snapshotId), None, body)
        tokens = decode_protobuf_array(z, MBSFileAuthToken)
        z = MBSFileAuthTokens()
        for t in tokens:
            toto = z.tokens.add()
            toto.FileID = h[t.FileID]
            toto.AuthToken = t.AuthToken
        return z

    def authorizeGet(self, tokens,snapshot):
        self.headers2["x-apple-mmcs-auth"]= "%s %s" % (tokens.tokens[0].FileID.encode("hex"), tokens.tokens[0].AuthToken)
        body = tokens.SerializeToString()

        filegroups = probobuf_request(self.content_host, "POST", "/%d/authorizeGet" % self.dsPrsID, body, self.headers2, FileGroups)
        #print filegroups
        filechunks = {}
        for group in filegroups.file_groups:
            for container_index in xrange(len(group.storage_host_chunk_list)):
                data = self.downloadChunks(group.storage_host_chunk_list[container_index])
                for file_ref in group.file_checksum_chunk_references:
                    if not self.files.has_key(file_ref.file_checksum):
                        continue
                    decrypted_chunks = filechunks.setdefault(file_ref.file_checksum, {})
                    for i in xrange(len(file_ref.chunk_references)):
                        ref = file_ref.chunk_references[i]
                        if ref.container_index == container_index:
                            decrypted_chunks[i] = data[ref.chunk_index]
                    if len(decrypted_chunks) == len(file_ref.chunk_references):
                        f = self.files[file_ref.file_checksum]
                        self.writeFile(f, decrypted_chunks,snapshot)
                        del self.files[file_ref.file_checksum]

        return filegroups

    def getComplete(self, mmcs_auth):
        self.headers2["x-apple-mmcs-auth"] = mmcs_auth
        body = ""
        probobuf_request(self.content_host, "POST", "/%d/getComplete" % self.dsPrsID, body, self.headers2)

    def downloadChunks(self, storage_host):
        headers = {}
        for h in storage_host.host_info.headers:
            headers[h.name] = h.value
        d = probobuf_request(storage_host.host_info.hostname,
                         storage_host.host_info.method,
                         storage_host.host_info.uri, "", headers)
        decrypted = []
        i = 0
        for chunk in storage_host.chunk_info:
            dchunk = decrypt_chunk(d[i:i+chunk.chunk_length], chunk.chunk_encryption_key, chunk.chunk_checksum)
            if dchunk:
                decrypted.append(dchunk)
                i += chunk.chunk_length
        return decrypted

    def writeFile(self, f, decrypted_chunks,snapshot):
        if not os.path.exists(os.path.join(self.outputFolder, re.sub(r'[:|*<>?"]', "_", "snapshot_"+str(snapshot)+"/"+f.Domain))):
            os.makedirs(os.path.join(self.outputFolder, re.sub(r'[:|*<>?"]', "_", "snapshot_"+str(snapshot)+"/"+f.Domain)))

        path = os.path.join(self.outputFolder, re.sub(r'[:|*<>?"]', "_", "snapshot_"+str(snapshot)+"/"+f.Domain+"/"+f.RelativePath))
        #print '\t',f
        print '\t',f.Domain,'\t',path
        makedirs(os.path.dirname(path))
        ff = open(path, "wb")
        h = hashlib.sha1()
        for i in xrange(len(decrypted_chunks)):
            d = decrypted_chunks[i]
            h.update(d)
            ff.write(d)
        ff.close()

        #If file is encrypted
        if f.Attributes.EncryptionKey:
            EncryptionKey = f.Attributes.EncryptionKey
            ProtectionClass = struct.unpack(">L", EncryptionKey[0x18:0x1C])[0]
            if ProtectionClass == f.Attributes.ProtectionClass:
                if f.Attributes.EncryptionKeyVersion and f.Attributes.EncryptionKeyVersion == 2:
                    assert self.kb.uuid == EncryptionKey[:0x10]
                    keyLength = struct.unpack(">L", EncryptionKey[0x20:0x24])[0]
                    assert keyLength == 0x48
                    wrapped_key = EncryptionKey[0x24:]
                else:
                    wrapped_key = EncryptionKey[0x1C:]
                filekey = self.kb.unwrapCurve25519(ProtectionClass, wrapped_key)
                if not filekey:
                    print "Failed to unwrap file key for file %s !!!" % f.RelativePath
                else:
                    print "\tfilekey",filekey.encode("hex")
                    self.decryptProtectedFile(path, filekey, f.Attributes.DecryptedSize)
            else:
                print "\tUnable to decrypt file, possible old backup format", f.RelativePath
                #hexdump(EncryptionKey)

    def decryptProtectedFile(self, path, filekey, DecryptedSize=0):
        ivkey = hashlib.sha1(filekey).digest()[:16]
        h = hashlib.sha1()
        sz = os.path.getsize(path)
        #iOS 5 trailer = uint64 sz + sha1 of encrypted file
        #assert (sz % 0x1000) == 0x1C
        oldpath = path + ".encrypted"
        try:
            os.rename(path, oldpath)
        except:
            pass
        f1 = open(oldpath, "rb")
        f2 = open(path, "wb")
        n = (sz / 0x1000)
        if DecryptedSize:
            n += 1
        for block in xrange(n):
            iv = AESencryptCBC(self.computeIV(block * 0x1000), ivkey)
            data = f1.read(0x1000)
            h.update(data)
            f2.write(AESdecryptCBC(data, filekey, iv))
        if DecryptedSize == 0: #old iOS 5 format
            trailer = f1.read(0x1C)
            DecryptedSize = struct.unpack(">Q", trailer[:8])[0]
            assert h.digest() == trailer[8:]
        f1.close()
        f2.truncate(DecryptedSize)
        f2.close()

    def computeIV(self, lba):
        iv = ""
        lba &= 0xffffffff
        for _ in xrange(4):
            if (lba & 1):
                lba = 0x80000061 ^ (lba >> 1);
            else:
                lba = lba >> 1;
            iv += struct.pack("<L", lba)
        return iv

    def download(self,backupUDID,fast):
        mbsbackup = self.getBackup(backupUDID)
        print "Downloading backup %s" % backupUDID.encode("hex")
        self.outputFolder = os.path.join(self.outputFolder, backupUDID.encode("hex"))
        makedirs(self.outputFolder)
        #print backup_summary(mbsbackup)
        #print mbsbackup.Snapshot.Attributes.KeybagUUID.encode("hex")
        keys = self.getKeys(backupUDID)
        if not keys or not len(keys.Key):
            print "getKeys FAILED!"
            return
        print "Got OTA Keybag"

        self.kb = Keybag(keys.Key[1].KeyData)
        if not self.kb.unlockBackupKeybagWithPasscode(keys.Key[0].KeyData):
            print "Unable to unlock OTA keybag !"
            return


        print "Available Snapshots: ", mbsbackup.Snapshot.SnapshotID
        for snapshot in xrange(1, mbsbackup.Snapshot.SnapshotID+1):
            print "Listing snapshot..."
            files = self.listFiles(backupUDID, snapshot)
            print "Files in snapshot %s : %s" % (snapshot,len(files))
            files2 = []
            if fast=='y':
                for f in files:
                    if 'AddressBook.sqlitedb' in f.RelativePath or 'Calendar.sqlitedb' in f.RelativePath or 'sms.db' in f.RelativePath or 'call_history.db' in f.RelativePath or '.JPG'  in f.RelativePath :
                        files2.append(f)
                files = files2
                if len(files):
                    authTokens = self.getFiles(backupUDID, snapshot, files)
                    #print authTokens
                    self.authorizeGet(authTokens,snapshot)


            if fast=='n':
                if len(files):
                    authTokens = self.getFiles(backupUDID, snapshot, files)
                    #print authTokens
                    self.authorizeGet(authTokens,snapshot)




def download_backup(login, password, outputFolder):
    print 'Working with %s : %s' % (login,password)
    print 'Output directory :', outputFolder

    auth = "Basic %s" % base64.b64encode("%s:%s" % (login,password))
    authenticateResponse = plist_request("setup.icloud.com", "POST", "/setup/authenticate/$APPLE_ID$", "",{"Authorization": auth})
    if not authenticateResponse:
        print "Invalid Apple ID/password ?"
        return

    dsPrsID = authenticateResponse["appleAccountInfo"]["dsPrsID"]
    auth = "Basic %s" % base64.b64encode("%s:%s" % (dsPrsID, authenticateResponse["tokens"]["mmeAuthToken"]))
    account_settings = plist_request("setup.icloud.com", "POST", "/setup/get_account_settings", "",{"Authorization": auth, "X-MMe-Client-Info": Client_Info, "User-Agent": USER_AGENT_UBD})
    auth = "X-MobileMe-AuthToken %s" % base64.b64encode("%s:%s" % (dsPrsID, authenticateResponse["tokens"]["mmeAuthToken"]))
    client = MobileBackupClient(account_settings, dsPrsID, auth, outputFolder)

    mbsacct = client.getAccount()


    i = 0
    print "Available Devices: ",len(mbsacct.backupUDID)
    for device in mbsacct.backupUDID:
        print "===[",i,"]==="
        print "\tUDID: ",client.getBackup(device).backupUDID.encode("hex")
        print "\tDevice: ",client.getBackup(device).Attributes.MarketingName
        print "\tSize: ",sizeof_fmt(client.getBackup(device).QuotaUsed)
        print "\tLastUpdate: ",datetime.utcfromtimestamp(client.getBackup(device).Snapshot.LastModified)
        i = i+1


    id = raw_input("\nSelect backup to download: ")
    #client.download(mbsacct.backupUDID[int(z)])
    fast = raw_input("\nDownload only AddressBook,SMS,Photos (y/n): ")
    client.download(mbsacct.backupUDID[int(id)],fast)


def backup_summary(mbsbackup):
    d = datetime.utcfromtimestamp(mbsbackup.Snapshot.LastModified)
    return "%s %s %s %s" % (str(d), mbsbackup.Attributes.MarketingName, mbsbackup.Snapshot.Attributes.DeviceName, mbsbackup.Snapshot.Attributes.ProductVersion)



appleid = sys.argv[1]
password = sys.argv[2]
outputdir = 'output'

download_backup(appleid,password,outputdir)
