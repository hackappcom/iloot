#!/usr/bin/env python

# from __future__ import print_function

from datetime import datetime
from httplib import HTTPSConnection
from pprint import pprint
import argparse
import base64
import errno
import getpass
import hashlib
import os
import plistlib
import re
import struct
import sys
import urllib
import urlparse

import hurry.filesize
from chunkserver_pb2 import FileGroups
from crypto.aes import AESencryptCBC, AESdecryptCBC, AESdecryptCFB
from icloud_pb2 import MBSAccount, MBSBackup, MBSKeySet, MBSFile, MBSFileAuthToken, MBSFileAuthTokens
from keystore.keybag import Keybag
from pbuf import decode_protobuf_array, encode_protobuf_array
from util import hexdump

CLIENT_INFO = "<iPhone2,1> <iPhone OS;5.1.1;9B206> <com.apple.AppleAccount/1.0 ((null)/(null))>"
USER_AGENT_UBD = "ubd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
USER_AGENT_MOBILE_BACKUP = "MobileBackup/5.1.1 (9B206; iPhone3,1)"
USER_AGENT_BACKUPD = "backupd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
CLIENT_INFO_BACKUP = "<N88AP> <iPhone OS;5.1.1;9B206> <com.apple.icloud.content/211.1 (com.apple.MobileBackup/9B206)>"

ITEM_TYPES_TO_FILE_NAMES = {
    'address_book': "AddressBook.sqlitedb",
    'calendar': "Calendar.sqlitedb",
    'call_history': "call_history.db",
    'photos': ".JPG",
    'sms': "sms.db",
    'voicemails': "Voicemail",
}

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

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
    conn = HTTPSConnection(host)
    request = conn.request(method, url, body, headers)
    response = conn.getresponse()
    if response.status != 200:
        print "Request %s returned code %d" % (url, response.status)
        return

    return plistlib.readPlistFromString(response.read())

def probobuf_request(host, method, url, body, headers, msg=None):
    conn = HTTPSConnection(host)
    request = conn.request(method, url, body, headers)
    response = conn.getresponse()
    length = response.getheader("content-length")

    if length is None:
        length = 0
    else:
        length = int(length)

    data = response.read()

    while len(data) < length:
        d = response.read()
        data += d

    conn.close()
    if msg == None:
        return data

    res = msg()
    res.ParseFromString(data)
    return res


class URLFactory(object):
    def __init__(self, base=None):
        self.components = []
        self.base = base

        if self.base is not None:
            self.components.append(self.base)

    def __getattr__(self, k):
        self.components.append(k)
        return self

    def __getitem__(self, k):
        self.components.append(str(k))
        return self

    def __call__(self, *args, **kwargs):
        url = "/{}".format("/".join(self.components))

        self.components = []
        if self.base is not None:
            self.components.append(self.base)

        if len(kwargs) > 0:
            params = urllib.urlencode(kwargs)
            return "{}?{}".format(url, params)
        else:
            return url


MBS = URLFactory("mbs")
URL = URLFactory()

def host_from_url(url):
    return urlparse.urlparse(url).hostname

class MobileBackupClient(object):
    def __init__(self, account_settings, dsPrsID, auth, output_folder):
        mobilebackup_url = account_settings["com.apple.mobileme"]["com.apple.Dataclass.Backup"]["url"]
        content_url = account_settings["com.apple.mobileme"]["com.apple.Dataclass.Content"]["url"]

        self.mobilebackup_host = host_from_url(mobilebackup_url)
        self.content_host = host_from_url(content_url)
        self.dsPrsID = dsPrsID
        self.headers = {
            'Authorization': auth,
            'X-MMe-Client-Info': CLIENT_INFO,
            'User-Agent': USER_AGENT_MOBILE_BACKUP,
            'X-Apple-MBS-Protocol-Version': "1.7"
        }
        self.headers2 = {
            'x-apple-mmcs-proto-version': "3.3",
            'x-apple-mmcs-dataclass': "com.apple.Dataclass.Backup",
            'x-apple-mme-dsid': str(self.dsPrsID),
            'User-Agent': USER_AGENT_BACKUPD,
            'Accept': "application/vnd.com.apple.me.ubchunk+protobuf",
            'Content-Type': "application/vnd.com.apple.me.ubchunk+protobuf",
            'x-mme-client-info': CLIENT_INFO_BACKUP
        }

        self.files = {}
        self.output_folder = output_folder

    def mobile_backup_request(self, method, url, msg=None, body=""):
        return probobuf_request(self.mobilebackup_host, method, url, body, self.headers, msg)

    def get_account(self):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID](), MBSAccount)

    def get_backup(self, backupUDID):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")](), MBSBackup)

    def get_keys(self, backupUDID):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")].getKeys(), MBSKeySet)

    def list_files(self, backupUDID, snapshotId):
        files = self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")][snapshotId].listFiles(offset=0, limit=100))
        offset = 100
        files2 = 1
        while files2:
            files2 = self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")][snapshotId].listFiles(offset=offset, limit=100))
            if files2:
                offset += 100
                files = files + files2
                print "\tShifting offset: ", offset

        return decode_protobuf_array(files, MBSFile)

    def get_files(self, backupUDID, snapshotId, files):
        r = []
        h = {}
        for file in files:
            if file.Size == 0:
                continue

            ff = MBSFile()
            ff.FileID = file.FileID
            h[file.FileID] = file.Signature
            r.append(ff)
            self.files[file.Signature] = file

        body = encode_protobuf_array(r)
        z = self.mobile_backup_request("POST", MBS[self.dsPrsID][backupUDID.encode("hex")][snapshotId].getFiles(), None, body)
        tokens = decode_protobuf_array(z, MBSFileAuthToken)
        z = MBSFileAuthTokens()

        for token in tokens:
            toto = z.tokens.add()
            toto.FileID = h[token.FileID]
            toto.AuthToken = token.AuthToken

        return z

    def authorize_get(self, tokens, snapshot):
        self.headers2["x-apple-mmcs-auth"]= "%s %s" % (tokens.tokens[0].FileID.encode("hex"), tokens.tokens[0].AuthToken)
        body = tokens.SerializeToString()

        file_groups = probobuf_request(self.content_host, "POST", URL[self.dsPrsID].authorizeGet(), body, self.headers2, FileGroups)
        file_chunks = {}
        for group in file_groups.file_groups:
            for container_index, container in enumerate(group.storage_host_chunk_list):
                data = self.download_chunks(container)
                for file_ref in group.file_checksum_chunk_references:
                    if file_ref.file_checksum not in self.files:
                        continue

                    decrypted_chunks = file_chunks.setdefault(file_ref.file_checksum, {})

                    for i, reference in enumerate(file_ref.chunk_references):
                        if reference.container_index == container_index:
                            decrypted_chunks[i] = data[reference.chunk_index]

                    if len(decrypted_chunks) == len(file_ref.chunk_references):
                        file = self.files[file_ref.file_checksum]
                        try:
                            self.write_file(file, decrypted_chunks, snapshot)
                        except:
                            raise
                        else:
                            del self.files[file_ref.file_checksum]

        return file_groups

    def get_complete(self, mmcs_auth):
        self.headers2["x-apple-mmcs-auth"] = mmcs_auth
        body = ""
        probobuf_request(self.content_host, "POST", URL[self.dsPrsID].getComplete(), body, self.headers2)

    def download_chunks(self, container):
        headers = {}
        # XXX
        for header in container.host_info.headers:
            headers[header.name] = header.value

        d = probobuf_request(container.host_info.hostname,
                         container.host_info.method,
                         container.host_info.uri, "", headers)
        decrypted = []
        i = 0
        for chunk in container.chunk_info:
            dchunk = decrypt_chunk(d[i:i+chunk.chunk_length], chunk.chunk_encryption_key, chunk.chunk_checksum)
            if dchunk:
                decrypted.append(dchunk)
                i += chunk.chunk_length

        return decrypted

    def write_file(self, file, decrypted_chunks, snapshot):
        directory = os.path.join(self.output_folder, re.sub(r'[:|*<>?"]', "_", "snapshot_"+str(snapshot)+"/"+file.Domain))
        mkdir_p(directory)
        path = os.path.join(directory, file.RelativePath)

        print '\t', file.Domain, '\t', path
        with open(path, "wb") as ff:
            hash = hashlib.sha1()
            for key, chunk in decrypted_chunks.iteritems():
                hash.update(chunk)
                ff.write(chunk)

        # If file is encrypted
        if file.Attributes.EncryptionKey:
            key = file.Attributes.EncryptionKey
            ProtectionClass = struct.unpack(">L", key[0x18:0x1C])[0]
            if ProtectionClass == file.Attributes.ProtectionClass:
                if file.Attributes.EncryptionKeyVersion and file.Attributes.EncryptionKeyVersion == 2:
                    assert self.kb.uuid == key[:0x10]
                    keyLength = struct.unpack(">L", key[0x20:0x24])[0]
                    assert keyLength == 0x48
                    wrapped_key = key[0x24:]
                else:
                    wrapped_key = key[0x1C:]

                filekey = self.kb.unwrapCurve25519(ProtectionClass, wrapped_key)

                if not filekey:
                    print "Failed to unwrap file key for file %s !!!" % file.RelativePath
                else:
                    print "\tfilekey", filekey.encode("hex")
                    self.decrypt_protected_file(path, filekey, file.Attributes.DecryptedSize)
            else:
                print "\tUnable to decrypt file, possible old backup format", file.RelativePath

    def decrypt_protected_file(self, path, filekey, decrypted_size=0):
        ivkey = hashlib.sha1(filekey).digest()[:16]
        hash = hashlib.sha1()
        sz = os.path.getsize(path)

        oldpath = path + ".encrypted"
        try:
            os.rename(path, oldpath)
        except:
            pass

        with open(oldpath, "wb") as old_file:
            with open(path, "wb") as new_file:
                n = sz / 0x1000
                if decrypted_size:
                    n += 1

                for block in xrange(n):
                    iv = AESencryptCBC(self.computeIV(block * 0x1000), ivkey)
                    old_data = old_file.read(0x1000)
                    hash.update(old_data)
                    new_file.write(AESdecryptCBC(old_data, filekey, iv))

                if decrypted_size == 0: #old iOS 5 format
                    trailer = old_file.read(0x1C)
                    decrypted_size = struct.unpack(">Q", trailer[:8])[0]
                    assert hash.digest() == trailer[8:]

                new_file.truncate(decrypted_size)

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

    def download(self, backupUDID, item_types):
        mbsbackup = self.get_backup(backupUDID)
        self.output_folder = os.path.join(self.output_folder, backupUDID.encode("hex"))

        print "Downloading backup {} to {}".format(backupUDID.encode("hex"), self.output_folder)

        try:
            mkdir_p(self.output_folder)
        except OSError:
            print "Directory \"{}\" already exists.".format(self.output_folder)
            return

        keys = self.get_keys(backupUDID)
        if not keys or not len(keys.Key):
            print "get_keys FAILED!"
            return

        print "Got OTA Keybag"

        self.kb = Keybag(keys.Key[1].KeyData)
        if not self.kb.unlockBackupKeybagWithPasscode(keys.Key[0].KeyData):
            print "Unable to unlock OTA keybag !"
            return

        print "Available Snapshots: ", mbsbackup.Snapshot.SnapshotID
        for snapshot in xrange(1, mbsbackup.Snapshot.SnapshotID+1):
            print "Listing snapshot..."
            files = self.list_files(backupUDID, snapshot)
            print "Files in snapshot %s : %s" % (snapshot, len(files))

            def matches_allowed_item_types(file):
                return any(ITEM_TYPES_TO_FILE_NAMES[item_type] in file.RelativePath \
                        for item_type in item_types)

            if len(item_types) > 0:
                files = filter(matches_allowed_item_types, files)

            if len(files):
                authTokens = self.get_files(backupUDID, snapshot, files)
                self.authorize_get(authTokens, snapshot)


def download_backup(login, password, output_folder, types):
    print 'Working with %s : %s' % (login, password)
    print 'Output directory :', output_folder

    auth = "Basic %s" % base64.b64encode("%s:%s" % (login, password))
    authenticateResponse = plist_request("setup.icloud.com", "POST", "/setup/authenticate/$APPLE_ID$", "", {"Authorization": auth})
    if not authenticateResponse:
        print "Invalid Apple ID/password ?"
        return

    dsPrsID = authenticateResponse["appleAccountInfo"]["dsPrsID"]
    auth = "Basic %s" % base64.b64encode("%s:%s" % (dsPrsID, authenticateResponse["tokens"]["mmeAuthToken"]))

    headers = {
        'Authorization': auth,
        'X-MMe-Client-Info': CLIENT_INFO,
        'User-Agent': USER_AGENT_UBD
    }
    account_settings = plist_request("setup.icloud.com", "POST", "/setup/get_account_settings", "", headers)
    auth = "X-MobileMe-AuthToken %s" % base64.b64encode("%s:%s" % (dsPrsID, authenticateResponse["tokens"]["mmeAuthToken"]))
    client = MobileBackupClient(account_settings, dsPrsID, auth, output_folder)

    mbsacct = client.get_account()

    print "Available Devices: ", len(mbsacct.backupUDID)
    for i, device in enumerate(mbsacct.backupUDID):
        backup = client.get_backup(device)
        print "===[", i, "]==="
        print "\tUDID: ", backup.backupUDID.encode("hex")
        print "\tDevice: ", backup.Attributes.MarketingName
        print "\tSize: ", hurry.filesize.size(backup.QuotaUsed)
        print "\tLastUpdate: ", datetime.utcfromtimestamp(backup.Snapshot.LastModified)

    if i == 0:
        UDID = mbsacct.backupUDID[0]
    else:
        id = raw_input("\nSelect backup to download (0-{}): ".format(i))
        UDID = mbsacct.backupUDID[int(id)]

    client.download(UDID, types)

def backup_summary(mbsbackup):
    d = datetime.utcfromtimestamp(mbsbackup.Snapshot.LastModified)
    return "%s %s %s %s" % (str(d), mbsbackup.Attributes.MarketingName, mbsbackup.Snapshot.Attributes.DeviceName, mbsbackup.Snapshot.Attributes.ProductVersion)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='iloot')
    parser.add_argument("apple_id", type=str, default=None, help="Apple ID")
    parser.add_argument("password", type=str, default=None, help="Password")
    parser.add_argument("--output", "-o", type=str, default="output", help="Output Directory")
    parser.add_argument("--item-types", "-t", nargs="+", type=str, default="",
            help="Only download the specified item types. Options include " \
                    "address_book, calendar, sms, call_history, voicemails, " \
                    "and photos. E.g., --types sms voicemail")

    args = parser.parse_args()
    download_backup(args.apple_id, args.password, args.output, args.item_types)

