"""Import/export tools for krb5 binary data formats.

This module contains classes for reading and writing MIT Kerberos V5 de-facto
binary file formats.  The objects behave as lists of dictionaries containing the
attributes of each key.

- Keytab: Machine credentials key table file (e.g. /etc/krb5.keytab)
- CredentialCache: User credentials cache (e.g. /tmp/krb5cc_*)

Example:
    >>> import krb5format
    >>> keytab = krb5format.Keytab('/etc/krb5.keytab')
    >>> for entry in keytab:
    ...     print "%03s  %s" % (entry['key']['type'], entry['principal']['value'])
    ... 
      1  host/hostname.domain@REALM
      3  host/hostname.domain@REALM
     17  host/hostname.domain@REALM
     18  host/hostname.domain@REALM
     23  host/hostname.domain@REALM
      1  host/HOSTNAME@REALM
      3  host/HOSTNAME@REALM
     17  host/HOSTNAME@REALM
     18  host/HOSTNAME@REALM
     23  host/HOSTNAME@REALM
      1  HOSTNAME$@REALM
      3  HOSTNAME$@REALM
     17  HOSTNAME$@REALM
     18  HOSTNAME$@REALM
     23  HOSTNAME$@REALM
      1  root/hostname@REALM
      3  root/hostname@REALM
     17  root/hostname@REALM
     18  root/hostname@REALM
     23  root/hostname@REALM
"""

from __future__ import print_function
import re
import os
import struct
import datetime
import calendar
import time

char   = struct.Struct('!B')
uint16 = struct.Struct('!H')
int32  = struct.Struct('!i')
uint32 = struct.Struct('!I')

class Krb5File(list):
    """A base class for CredentialCache and Keytab.
    
    Don't use this directly; instead create one of the more specific objects for
    the actual format being used.  In either case the object acts as a list of
    dictionaries containing the key data.
    """

    def __init__(self, filename):
        list.__init__(self)
        self.array = uint16
        self.load(filename)

    def load(self, filename):
        with open(filename, 'rb') as f:
            self.version = self._read_version(f)
            if self.version == 0x0504:
                self.array = uint32
            self._load_intro(f)
            while 1:
                try:
                    entry = self._load_entry(f)
                except EOFError:
                    break
                self.append(entry)
        return self

    def _load_intro(self, f):
        pass

    def _read_version(self, f):
        return uint16.unpack(f.read(2))[0]

    def _read_array(self, f):
        length, = self.array.unpack(f.read(self.array.size))
        data = f.read(length)
        return data

    def _read_principal(self, f):
        princ = {}
        try:
            if self.version == 0x0504:
                princ["name_type"], = uint32.unpack(f.read(4))
            num_components, = self.array.unpack(f.read(self.array.size))
        except struct.error:
            raise EOFError
        realm = self._read_array(f)
        components = []
        for i in range(num_components):
            components.append(self._read_array(f))
        if self.version == 0x0502:
            princ["name_type"], = uint32.unpack(f.read(4))
        princ["value"] = "/".join(components) + '@' + realm
        return princ

    def _read_time(self, f):
        return uint32.unpack(f.read(4))[0]

    def _read_keyblock(self, f):
        key = {}
        key["type"], = uint16.unpack(f.read(2))
        if self.version > 0x0502:
            key["etype"] = f.read(2)
        keylen, = uint16.unpack(f.read(2))
        key["val"] = f.read(keylen)
        return key

    def _make_array(self, arr):
        return self.array.pack(len(arr)) + arr


# https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html
class Keytab(Krb5File):
    """A krb5 keytab file (as in /etc/krb5.keytab)."""

    def save(self, filename):
        """Write a new keytab to the given filename."""
        with open(filename, 'wb') as f:
            os.chmod(filename, 0o600)
            f.write(uint16.pack(self.version))
            for key in self:
                self.__write_entry(key, f)

    def filter(self, pattern):
        """Remove keytab principals not matching a given regex pattern."""
        princs = re.compile(pattern)
        keys = filter(lambda k: princs.match(k["principal"]["value"]), self)
        other_keys = []
        for key in self:
            if key not in keys:
                other_keys.append(key)
        for key in other_keys:
                self.remove(key)

    def klist(self):
        """Print klist-like text to stdout for this keytab."""
        FMT = '%m/%d/%y %H:%M:%S'
        print("KVNO Timestamp         Principal")
        print("-"*4 +" " + "-"*17 + " " + "-"*56)
        for key in self:
            kvno = key["vno8"]
            timestamp = datetime.datetime.fromtimestamp(key["timestamp"])
            timestamp = timestamp.strftime(FMT)
            principal = key["principal"]["value"]
            enctype = key["key"]["type"]
            print("%4d %s %s (%s)" % (kvno, timestamp, principal, enctype))

    def _load_entry(self, f):
        size = self.__get_entry_size(f)
        while size < 0:
            f.read(-size)
            size = self.__get_entry_size(f)
        start = f.tell()
        entry = {}
        entry["principal"] = self._read_principal(f)
        entry["timestamp"] = self._read_time(f)
        entry["vno8"]      = self._read_vno8(f)
        entry["key"]       = self._read_keyblock(f)
        entry["vno"]       = self._read_vno(f, size, start)
        return entry

    def _read_vno8(self, f):
        return char.unpack(f.read(1))[0]

    def _read_vno(self, f, size, start):
        finish = f.tell()
        remaining = size - (finish - start)
        vno = None
        if remaining >= 4:
            vno, = uint32.unpack(f.read(4))
            remaining -= 4
        if remaining > 0:
            f.read(remaining)
        return vno

    def __get_entry_size(self, f):
        data = f.read(4)
        if len(data) < 4:
            raise EOFError
        size, = int32.unpack(data)
        return size

    def __write_entry(self, entry, f):
        data = ""
        princ, realm = entry["principal"]["value"].split('@')
        components = princ.split('/')
        data += uint16.pack(len(components))
        data += self._make_array(realm)
        for c in components:
            data += self._make_array(c)
        data += uint32.pack(entry["principal"]["name_type"])
        data += uint32.pack(entry["timestamp"])
        data += char.pack(entry["vno8"])
        data += uint16.pack(entry["key"]["type"])
        data += self._make_array(entry["key"]["val"])
        if entry["vno"]:
            data += uint32.pack(entry["vno"])
        data = int32.pack(len(data)) + data
        f.write(data)


# https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html
class CredentialCache(Krb5File):
    """A krb5 credential cache file (as in /tmp/krb5cc_*)."""

    def is_tgt_expired(self, secs=0):
        """True if the TGT is expired, or will expire soon.
        
        secs -- time limit for ticket expiration (default 0)
        """
        for key in self:
            server = key["server"]["value"]
            service = server.split('/')[0]
            if service == "krbtgt":
                expires = key["times"]["endtime"]
                now = calendar.timegm(datetime.datetime.now().timetuple()) + time.timezone
                if expires <= now + secs:
                    return True
                return False

    def _load_intro(self, f):
        self.headers = self._read_headers(f)
        self.default_princ = self._read_principal(f)

    def _load_entry(self, f):
        cred = {}
        cred["client"]     = self._read_principal(f)
        cred["server"]     = self._read_principal(f)
        cred["key"]        = self._read_keyblock(f)
        cred["times"]      = self._read_times(f)
        cred["is_skey"],   = char.unpack(f.read(1))
        cred["tktflags"],  = struct.unpack("<L", f.read(4))
        cred["addrs"]      = self._read_segments(f)
        cred["authdata"]   = self._read_segments(f)
        cred["ticket"]     = self._read_array(f)
        cred["ticket2"]    = self._read_array(f)
        return cred

    def _read_headers(self, f):
        headerlen, = uint16.unpack(f.read(2))
        pos = f.tell()
        headers = []
        while (f.tell() < pos + headerlen):
            tag, = uint16.unpack(f.read(2))
            taglen, = uint16.unpack(f.read(2))
            tagdata = f.read(taglen)
            headers.append((tag, tagdata))
        return headers

    def _read_times(self, f):
        times = {}
        times["authtime"]   = self._read_time(f)
        times["starttime"]  = self._read_time(f)
        times["endtime"]    = self._read_time(f)
        times["renew_till"] = self._read_time(f)
        return times

    def _read_segments(self, f):
        num_segs, = uint32.unpack(f.read(4))
        segs = []
        for i in range(num_segs):
            segs.append(self._read_array(f))
        return segs
