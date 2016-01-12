#!/usr/bin/env python
# from __future__ import print_function

import gevent
from gevent.pool import Pool
from gevent import monkey
monkey.patch_all()

from datetime import datetime
from httplib import HTTPSConnection
from pprint import pprint
import ssl, socket
import argparse
import base64
import errno
import hashlib
import os
import plistlib
import re
import struct
import urllib
import urlparse

import hurry.filesize
from chunkserver_pb2 import FileGroups
from crypto.aes import AESencryptCBC, AESdecryptCBC, AESdecryptCFB
from icloud_pb2 import MBSAccount, MBSBackup, MBSKeySet, MBSFile, MBSFileAuthToken, MBSFileAuthTokens
from keystore.keybag import Keybag
from pbuf import decode_protobuf_array, encode_protobuf_array
from util import hexdump

CLIENT_INFO = "<iPhone6,2> <iPhone OS;9.0.2;13A452> <com.apple.AppleAccount/1.0 ((null)/(null))>"
USER_AGENT_UBD = "ubd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
USER_AGENT_MOBILE_BACKUP = "MobileBackup/9.0.2 (13A452; iPhone6,2)"
USER_AGENT_BACKUPD = "backupd (unknown version) CFNetwork/548.1.4 Darwin/11.0.0"
CLIENT_INFO_BACKUP = "<N88AP> <iPhone OS;9.0.2;13A452> <com.apple.icloud.content/211.1 (com.apple.MobileBackup/13A452)>"
DEFAULT_THREADS = 100
DOWNLOAD_CHUNKS_ATTEMPTS_MAX = 10
ITEM_TYPES_TO_FILE_NAMES = {
    'address_book': "addressbook.sqlitedb",
    'calendar': "Calendar.sqlitedb",
    'call_history': "call_history.db",
    'photos': ".jpg",
    'movies':".mov",
    'sms': "sms.db",
    'voicemails': "voicemail",
    'notes' : "notes."
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
    sock = socket.create_connection((conn.host, conn.port), conn.timeout, conn.source_address)
    conn.sock = ssl.wrap_socket(sock, conn.key_file, conn.cert_file, ssl_version=ssl.PROTOCOL_TLSv1)
    request = conn.request(method, url, body, headers)
    response = conn.getresponse()

    data = response.read()
    try:
        plist_data = plistlib.readPlistFromString(data)
    except:
        plist_data = None

    if response.status != 200:
        if plist_data is None:
            print "Request %s returned code %d" % (url, response.status)
        else:
            print "{}: {}".format(plist_data.title, plist_data.message)

        return

    return plist_data

def probobuf_request(host, method, url, body, headers, msg=None):
    conn = HTTPSConnection(host)
    sock = socket.create_connection((conn.host, conn.port), conn.timeout, conn.source_address)
    conn.sock = ssl.wrap_socket(sock, conn.key_file, conn.cert_file, ssl_version=ssl.PROTOCOL_TLSv1)
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

        self.chosen_snapshot_id = None
        self.combined = False
        self.itunes_style = False
        self.downloaded_files = []
        self.domain_filter = None
        self.threads = DEFAULT_THREADS

    def mobile_backup_request(self, method, url, msg=None, body=""):
        return probobuf_request(self.mobilebackup_host, method, url, body, self.headers, msg)

    def get_account(self):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID](), MBSAccount)

    def get_backup(self, backupUDID):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")](), MBSBackup)

    def get_keys(self, backupUDID):
        return self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")].getKeys(), MBSKeySet)

    def list_files(self, backupUDID, snapshotId):
        limit = 5000
        files = ""

        offset = 0
        new_files = self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")][snapshotId]['listFiles'](offset=offset, limit=limit))
        while new_files:
            files = files + new_files
            offset += limit

            new_files = self.mobile_backup_request("GET", MBS[self.dsPrsID][backupUDID.encode("hex")][snapshotId].listFiles(offset=offset, limit=limit))
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
        if len(tokens.tokens) == 0:
            return

        self.headers2["x-apple-mmcs-auth"]= "%s %s" % (tokens.tokens[0].FileID.encode("hex"), tokens.tokens[0].AuthToken)
        body = tokens.SerializeToString()

        file_groups = probobuf_request(self.content_host, "POST", URL[self.dsPrsID].authorizeGet(), body, self.headers2, FileGroups)
        file_chunks = {}
        pool = Pool(self.threads)

        containers = []
        for group in file_groups.file_groups:
            for container_index, container in enumerate(group.storage_host_chunk_list):
                containers.append([group, container_index, container])

        for res in pool.imap_unordered(self.download_chunks, containers):
            args, data = res
            group, container_index, container = args

            for file_ref in group.file_checksum_chunk_references:
                if file_ref.file_checksum not in self.files:
                    continue

                decrypted_chunks = file_chunks.setdefault(file_ref.file_checksum, {})

                for i, reference in enumerate(file_ref.chunk_references):
                    if reference.container_index == container_index:
                        if (len(data) > reference.chunk_index):
                            decrypted_chunks[i] = data[reference.chunk_index]
                        else:
                            break

                if len(decrypted_chunks) == len(file_ref.chunk_references):
                    file = self.files[file_ref.file_checksum]
                    try:
                        self.write_file(file, decrypted_chunks, snapshot)
                    except:
                        raise
                    else:
                        # With iTunes style we need to keep the file
                        if self.itunes_style :
                            self.downloaded_files.append(file)

                        del self.files[file_ref.file_checksum]

        pool.join()
        return file_groups

    def get_complete(self, mmcs_auth):
        self.headers2["x-apple-mmcs-auth"] = mmcs_auth
        body = ""
        probobuf_request(self.content_host, "POST", URL[self.dsPrsID].getComplete(), body, self.headers2)

    def download_chunks(self, args):
        group, container_index, container = args

        headers = {}
        # XXX
        for header in container.host_info.headers:
            headers[header.name] = header.value

        # Attempt to download chunks in the container maximum of DOWNLOAD_CHUNKS_ATTEMPTS_MAX times. Re-raise
        # the exception if still not successful.
        attempts = DOWNLOAD_CHUNKS_ATTEMPTS_MAX
        while attempts:
            try:
                d = probobuf_request(container.host_info.hostname,
                         container.host_info.method,
                         container.host_info.uri, "", headers)

                if attempts < DOWNLOAD_CHUNKS_ATTEMPTS_MAX:
                    print "Downloading chunks (container %d) - success on attempt %d" % \
                          (container_index, DOWNLOAD_CHUNKS_ATTEMPTS_MAX - attempts + 1)

            except Exception as e:
                print "Error downloading chunks (container %d) (%s) attempt %d of %d" % \
                      (container_index, repr(e), DOWNLOAD_CHUNKS_ATTEMPTS_MAX - attempts + 1, DOWNLOAD_CHUNKS_ATTEMPTS_MAX)
                attempts -= 1
                if 0 == attempts:
                    raise
            else:
                break

        decrypted = []
        i = 0
        for chunk in container.chunk_info:
            dchunk = decrypt_chunk(d[i:i+chunk.chunk_length], chunk.chunk_encryption_key, chunk.chunk_checksum)
            if dchunk:
                decrypted.append(dchunk)
                i += chunk.chunk_length

        return args, decrypted

    def write_file(self, file, decrypted_chunks, snapshot):
        path = self.create_output_path(file, snapshot)

        mkdir_p(os.path.dirname(path))

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
                wrapped_key = None
                filekey = None
                if file.Attributes.EncryptionKeyVersion and file.Attributes.EncryptionKeyVersion == 2:
                    if self.kb.uuid == key[:0x10]:
                        keyLength = struct.unpack(">L", key[0x20:0x24])[0]
                        if keyLength == 0x48:
                            wrapped_key = key[0x24:]
                else:
                    wrapped_key = key[0x1C:]

                if wrapped_key:
                    filekey = self.kb.unwrapCurve25519(ProtectionClass, wrapped_key)

                if not filekey:
                    print "Failed to unwrap file key for file %s !!!" % file.RelativePath
                else:
                    print "\tfilekey", filekey.encode("hex")
                    self.decrypt_protected_file(path, filekey, file.Attributes.DecryptedSize)
            else:
                print "\tUnable to decrypt file, possible old backup format", file.RelativePath

    def create_output_path(self, file, snapshot):
        # If the filename should be left in the iTunes backup style
        if self.itunes_style:
            if self.combined:
                directory = self.output_folder
            else:
                directory = os.path.join(self.output_folder, "snapshot_"+str(snapshot))

            path_hash = hashlib.sha1(file.Domain.encode('utf-8')+"-"+file.RelativePath.encode('utf-8')).hexdigest()
            path = os.path.join(directory, path_hash)
        else:
            if self.combined:
                directory = os.path.join(self.output_folder, re.sub(r'[:|*<>?"]', "_", file.Domain))
                path = os.path.join(directory, file.RelativePath)
            else:
                directory = os.path.join(self.output_folder, re.sub(r'[:|*<>?"]', "_", "snapshot_"+str(snapshot)+"/"+file.Domain))
                path = os.path.join(directory, file.RelativePath)

        return path

    def decrypt_protected_file(self, path, filekey, decrypted_size=0):
        ivkey = hashlib.sha1(filekey).digest()[:16]
        hash = hashlib.sha1()
        sz = os.path.getsize(path)

        oldpath = path + ".encrypted"
        try:
            os.rename(path, oldpath)
        except:
            pass

        with open(oldpath, "rb") as old_file:
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
                old_file.close()
                os.remove(oldpath) # Delete the encrypted file

    def computeIV(self, lba):
        iv = ""
        lba &= 0xffffffff
        for _ in xrange(4):
            if (lba & 1):
                lba = 0x80000061 ^ (lba >> 1)
            else:
                lba = lba >> 1

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

        self.kb = Keybag(keys.Key[-1].KeyData)
        if not self.kb.unlockBackupKeybagWithPasscode(keys.Key[0].KeyData):
            print "Unable to unlock OTA keybag !"
            return

        print "Available Snapshots: %d" % (mbsbackup.Snapshot.SnapshotID)
        if self.chosen_snapshot_id == None:
            if mbsbackup.Snapshot.SnapshotID > 3:
                snapshot_list = [1, mbsbackup.Snapshot.SnapshotID - 1, mbsbackup.Snapshot.SnapshotID]
            else:
                snapshot_list = range(1, mbsbackup.Snapshot.SnapshotID + 1)
        elif self.chosen_snapshot_id < 0:
            snapshot_list = [mbsbackup.Snapshot.SnapshotID + self.chosen_snapshot_id + 1] # Remember chosen_snapshot_id is negative
        else:
            snapshot_list = [self.chosen_snapshot_id]

        for snapshot in snapshot_list:
            print "Listing snapshot %d..." % (snapshot)
            files = self.list_files(backupUDID, snapshot)
            print "Files in snapshot %d" % (len(files))

            def matches_allowed_domain(a_file):
                return self.domain_filter in a_file.Domain

            def matches_allowed_item_types(a_file):
                return any(ITEM_TYPES_TO_FILE_NAMES[item_type] in a_file.RelativePath.lower() \
                        for item_type in item_types)

            def matches_missing_or_partial_files(a_file):
                path = self.create_output_path(a_file, snapshot)
                return not os.path.isfile(path) or os.stat(path).st_size != a_file.Size

            if self.domain_filter:
                files = filter(matches_allowed_domain, files)

            if len(item_types) > 0:
                files = filter(matches_allowed_item_types, files)

            print "Downloading %d files due to filter" % (len(files))

            if (self.keep_existing):
                file_count = len(files)
                files = filter(matches_missing_or_partial_files, files)
                print "Skipping %d files that have already been downloaded, " \
                    "downloading %d files" % ((file_count - len(files)), len(files))

            if len(files):
                authTokens = self.get_files(backupUDID, snapshot, files)
                if len(authTokens.tokens) > 0:
                    self.authorize_get(authTokens, snapshot)

                    if self.itunes_style:
                        self.write_info_plist(mbsbackup, snapshot)
                        self.write_manifest_mbdb(snapshot)
                else:
                  print "Unable to download snapshot. This snapshot may not have finished uploading yet."

            # Clean up self.files
            if not self.combined :
                self.downloaded_files = []


    # Writes a plist file in the output_directory simular to that created by iTunes during backup
    def write_info_plist(self, mbsbackup, snapshot):
        if self.combined:
            directory = self.output_folder
        else:
            directory = os.path.join(self.output_folder, "snapshot_"+str(snapshot))

        info_plist = {
            "Device Name" : mbsbackup.Attributes.DeviceClass,
            "Display Name" : mbsbackup.Attributes.DeviceClass,
            "Product Type" : mbsbackup.Attributes.ProductType,
            "Serial Number" : mbsbackup.Attributes.SerialNumber,
            "Target Type" : "Device",
            "iTunes Version" : "12.3",
            "Product Version" : "9.0.2",  # Must be higher than 4.0, current iTunes backup sets to 8.1.1
            "Target Identifier" : mbsbackup.backupUDID.encode("hex"),
            "Unique Identifier" : mbsbackup.backupUDID.encode("hex")
        }

        with open(directory+"/Info.plist", 'wb') as fp:
            plistlib.writePlist(info_plist, fp)

    def write_manifest_mbdb(self, snapshot):
        if self.combined:
            directory = self.output_folder
        else:
            directory = os.path.join(self.output_folder, "snapshot_"+str(snapshot))

        filename = os.path.join(directory, "Manifest.mbdb")

        # Generate the bare minimum MBDB file

        # Open file
        mbdb_file = open(filename, "wb")

        # Write file header
        mbdb_file.write("mbdb")
        mbdb_file.write("\x00\x00")

        # For each file
        for file in self.downloaded_files:
            # Write App Domain length
            mbdb_file.write( struct.pack('>h', len(file.Domain)) )
            # Write App Domain
            mbdb_file.write( file.Domain )
            # Write iPhone Filename length
            mbdb_file.write( struct.pack('>h', len(file.RelativePath)) )
            # Write iPhone Filename
            mbdb_file.write( file.RelativePath )
            # Write 0xFFFF for Link Target Length signifying that it is not present
            mbdb_file.write("\xFF\xFF")
            # Write 0xFFFF for SHAChecksum Length signifying the checksum is not present
            mbdb_file.write("\xFF\xFF")
            # Write 0xFFFF for the length of some unknown value, signifying it is not present
            mbdb_file.write("\xFF\xFF")
            # Write 0x27 bytes of 0x00, for the file properties as set by the iPhone during restore
            mbdb_file.write("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            # Write 0x00 for extended property count
            mbdb_file.write("\x00")

        # Close file
        mbdb_file.close()


def download_backup(login, password, output_folder, types, chosen_snapshot_id, combined, itunes_style, domain, threads, keep_existing):
    print 'Working with %s : %s' % (login, password)
    print 'Output directory :', output_folder

    auth = "Basic %s" % base64.b64encode("%s:%s" % (login, password))
    authenticateResponse = plist_request("setup.icloud.com", "POST", "/setup/authenticate/$APPLE_ID$", "", {"Authorization": auth})
    if not authenticateResponse:
        # There was an error authenticating the user.
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

    client.chosen_snapshot_id = chosen_snapshot_id
    client.combined = combined
    client.itunes_style = itunes_style
    client.domain_filter = domain
    client.threads = threads
    client.keep_existing = keep_existing

    mbsacct = client.get_account()

    print "Available Devices: ", len(mbsacct.backupUDID)
    if len(mbsacct.backupUDID) > 0:
        for i, device in enumerate(mbsacct.backupUDID):
            backup = client.get_backup(device)
            print "===[", i, "]==="
            print "\tUDID: ", backup.backupUDID.encode("hex")
            print "\tDevice: ", backup.Attributes.MarketingName
            print "\tVersion: ", backup.Snapshot.Attributes.ProductVersion
            print "\tSize: ", hurry.filesize.size(backup.QuotaUsed)
            print "\tLastUpdate: ", datetime.utcfromtimestamp(backup.Snapshot.LastModified)

        if i == 0:
            UDID = mbsacct.backupUDID[0]
        else:
            id = raw_input("\nSelect backup to download (0-{}): ".format(i))
            UDID = mbsacct.backupUDID[int(id)]

        client.download(UDID, types)

    else:
        print "There are no backups to download!"

def backup_summary(mbsbackup):
    d = datetime.utcfromtimestamp(mbsbackup.Snapshot.LastModified)
    return "%s %s %s %s" % (str(d), mbsbackup.Attributes.MarketingName, mbsbackup.Snapshot.Attributes.DeviceName, mbsbackup.Snapshot.Attributes.ProductVersion)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='iloot')
    parser.add_argument("apple_id", type=str, default=None, help="Apple ID")
    parser.add_argument("password", type=str, default=None, help="Password")

    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Download thread pool size")
    parser.add_argument("--output", "-o", type=str, default="output",
            help="Output Directory")

    parser.add_argument("--combined", action="store_true",
            help="Do not separate each snapshot into its own folder")

    parser.add_argument("--snapshot", type=int, default=None,
            help="Only download data the snapshot with the specified ID. " \
                    "Negative numbers will indicate relative position from " \
                    "newest backup, with -1 being the newest, -2 second, etc.")

    parser.add_argument("--itunes-style", action="store_true",
            help="Save the files in a flat iTunes-style backup, with " \
                    "mangled names")

    parser.add_argument("--item-types", "-t", nargs="+", type=str, default="",
            help="Only download the specified item types. Options include " \
                    "address_book, calendar, sms, call_history, voicemails, " \
                    "movies and photos. E.g., --types sms voicemail")

    parser.add_argument("--domain", "-d", type=str, default=None,
            help="Limit files to those within a specific application domain")

    parser.add_argument("--keep-existing", action="store_true",
            help="Do not download files that has already been downloaded in " \
                    "a previous run. Skip files that already exist locally " \
                    "and that has the same file size locally as in the backup.")

    args = parser.parse_args()
    download_backup(args.apple_id, args.password, args.output, args.item_types, args.snapshot, args.combined, args.itunes_style, args.domain, args.threads, args.keep_existing)

