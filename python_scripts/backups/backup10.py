import os
import re
import sqlite3
import plistlib

import struct

import hashlib
import binascii
import base64

from Crypto.Cipher import AES
from crypto.aes import AESdecryptCBC
from crypto.aeswrap import AESUnwrap

from util import readPlist, makedirs, parsePlist
from util import bplist

def warn(msg):
    print "WARNING: %s" % msg

MASK_SYMBOLIC_LINK = 0xa000
MASK_REGULAR_FILE = 0x8000
MASK_DIRECTORY = 0x4000

class MBFile(object):
    def __init__(self, domain, relative_path, flags, file_blob):
        self.domain = domain
        self.relative_path = relative_path
        self.flags = flags
        self.file_info = parsePlist(str(file_blob))

        self._parse_file_info()

    def _parse_file_info(self):
        self.file_hash = None
        objects = self.file_info['$objects']
        if objects[1].has_key('Digest'):
            if isinstance(objects[1]['Digest'], plistlib.Data):
                self.file_hash = objects[1]['Digest']
            elif isinstance(objects[1]['Digest'], bplist.BPListUID) and len(objects) >= objects[1]['Digest'].uid:
                p = objects[objects[1]['Digest'].uid]
                if isinstance(p, plistlib.Data):
                    self.file_hash = p.data
                elif isinstance(p, dict) and p.has_key('NS.data'):
                    self.file_hash = p['NS.data']

        self.protection_class = 0
        self.encryption_key = None
        self.protection_class = objects[1]['ProtectionClass']
        self.file_size = objects[1]['Size']
        self.mode = objects[1]['Mode']
        self.encryption_key = None

        if objects[1].has_key('EncryptionKey'):
            if isinstance(objects[1]['EncryptionKey'], plistlib.Data):
                self.encryption_key = objects[1]['EncryptionKey']
            elif isinstance(objects[1]['EncryptionKey'], bplist.BPListUID) and len(objects) >= objects[1]['EncryptionKey'].uid:
                p = objects[objects[1]['EncryptionKey'].uid]
                if isinstance(p, plistlib.Data):
                    self.encryption_key = p.data
                elif isinstance(p, dict) and p.has_key('NS.data'):
                    self.encryption_key = p['NS.data'].data

        self.target = None
        if objects[1].has_key('Target'):
            if isinstance(objects[1]['Target'], str):
                self.target = objects[1]['Target']
            elif isinstance(objects[1]['Target'], bplist.BPListUID) and len(objects) >= objects[1]['Target'].uid:
                p = objects[objects[1]['Target'].uid]
                if isinstance(p, str):
                    self.target = p
                elif isinstance(p, dict) and p.has_key('NS.string'):
                    self.target = p['NS.string']


    def type(self):
        return self.mode & 0xf000

    def is_symbolic_link(self):
        return self.type() == MASK_SYMBOLIC_LINK

    def is_regular_file(self):
        return self.type() == MASK_REGULAR_FILE

    def is_directory(self):
        return self.type() == MASK_DIRECTORY


class ManifestDB(object):
    def __init__ (self, backup_path, output_path, kb):
        self.files = {}
        self.backup_path = backup_path
        self.keybag = kb

	if kb.manifestKey != None:
            DB_key = kb.manifestKey[-40:]
            DB_class = int(binascii.hexlify(kb.manifestKey[:1]), 16)

            file_enc = open(os.path.join(backup_path,'Manifest.db'),"r")
            file_dec = open(os.path.join(output_path,'Manifest.db'),"w")

            key = self.keybag.unwrapKeyForClass(DB_class, DB_key)
            if not key:
                warn("Cannot unwrap key for {0}".format(out_file))
                return
            aes = AES.new(key, AES.MODE_CBC, "\x00"*16)

            while True:
                data = file_enc.read(8192)
                if not data:
                    break
                data2 = data = aes.decrypt(data)
                file_dec.write(data)

            file_enc.close()

            c = data2[-1]
            i = ord(c)
            if i < 17 and data2.endswith(c*i):
                file_dec.truncate(file_dec.tell() - i)
            else:
                warn("Bad padding, last byte = 0x%x !" % i)

            file_dec.close()

            conn = sqlite3.connect(os.path.join(output_path,'Manifest.db'))
	else:
            conn = sqlite3.connect(os.path.join(backup_path,'Manifest.db'))

        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # check for  10.0 < iOS < 10.1
	    try:
                cursor.execute("SELECT value FROM Properties WHERE key='salt'")
                salt = cursor.fetchone()[0]

                cursor.execute("SELECT value FROM Properties WHERE key='passwordHash'")
                hash = cursor.fetchone()[0]

                calculatedHash = hashlib.sha256(kb.password + str(salt)).hexdigest()

                if calculatedHash == binascii.hexlify(hash):
                    key = (hashlib.sha1(kb.password + str(salt)).digest())[:16]
                    iv = ''
                    for i in range(16):
                        iv += chr(i)
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    cryptedFileInfo = True
                else:
                    print "Hash mismatch"
                    return
            except:
                cryptedFileInfo = False
                

            for record in cursor.execute("SELECT fileID, domain, relativePath, flags, file FROM Files"):
                filename = record[0]
                domain = record[1]
                relative_path = record[2]
                flags = record[3]
                file_blob = record[4]
                if flags == 16:
                    warn("Flags == 16 for {0} {1} ({2})".format(domain, relative_path, file_blob))
                else:
                    if cryptedFileInfo:
                        file_blob = aes.decrypt(base64.b64decode(file_blob))

		    self.files[filename] = MBFile(domain, relative_path, flags, file_blob)

        finally:
            conn.close()


    def extract_backup(self, output_path):
        for mbfile in self.files.itervalues():
            if mbfile.is_directory():
                record_path = re.sub(r'[:|*<>?"]', "_", mbfile.relative_path)
                path = os.path.join(output_path, mbfile.domain, record_path)
                if not os.path.exists(path):
                    os.makedirs(path)

        for filename, mbfile in self.files.iteritems():
            if mbfile.is_regular_file() or mbfile.is_symbolic_link():
                self._extract_file(filename, mbfile, output_path)

    def _extract_file(self, filename, record, output_path):
         # adjust output file name
        if record.is_symbolic_link():
            out_file = record.target
        else:
            out_file = record.relative_path

        try:
            f1 = file(os.path.join(self.backup_path, filename[:2] ,filename), 'rb')

        except:
            warn("File %s (%s) has not been found" % (os.path.join(filename[:2] ,filename), record.relative_path))
            return


        # write output file
        out_file = re.sub(r'[:|*<>?"]', "_", out_file)
        output_path = os.path.join(output_path, record.domain, out_file)
        print("Writing %s" % output_path)
        f2 = file(output_path, 'wb')

        aes = None

        if record.encryption_key is not None and self.keybag: # file is encrypted!
            key = self.keybag.unwrapKeyForClass(record.protection_class, record.encryption_key[4:])
            if not key:
                warn("Cannot unwrap key for {0}".format(out_file))
                return
            aes = AES.new(key, AES.MODE_CBC, "\x00"*16)

        while True:
            data = f1.read(8192)
            if not data:
                break
            if aes:
                data2 = data = aes.decrypt(data)
            f2.write(data)

        f1.close()
        if aes:
            c = data2[-1]
            i = ord(c)
            if i < 17 and data2.endswith(c*i):
                f2.truncate(f2.tell() - i)
            else:
                warn("Bad padding, last byte = 0x%x !" % i)

        f2.close()
