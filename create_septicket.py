#!/usr/bin/env python3

# adapted create_apticket.py

import sys, plistlib
from pyasn1.type import constraint
from pyasn1.type.univ import *
from pyasn1.type.char import *
from pyasn1.type.namedtype import *
from pyasn1.type.tag import *
from pyasn1.type.opentype import *
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from binascii import hexlify

from pyasn1_modules import rfc5280


class APTicketMANB(Sequence):
    componentType = NamedTypes(
        NamedType("type", IA5String()),
        NamedType("payload", Set()),
    )
    tagSet = Sequence.tagSet.tagExplicitly(Tag(192, 32, 1296125506))


class APTicket(Sequence):
    componentType = NamedTypes(
        NamedType("type", IA5String()),
        NamedType("ver", Integer()),
        NamedType("manb", SetOf(APTicketMANB())),
        NamedType("unk", OctetString()),
        # NamedType('unk2', Any()),
        NamedType("cert", SequenceOf(rfc5280.Certificate())),
        # NamedType('unk4', OctetString())
    )


def find_build_identity(manifest, model):
    for o in manifest["BuildIdentities"]:
        if (
            o["Info"]["DeviceClass"] == model
            and "RestoreBehavior" in o["Info"]
            and o["Info"]["RestoreBehavior"] == "Erase"
        ):
            return o
    return None


def create_seq(name, value):
    name_hex_int = int(hexlify(name.encode()), 16)
    seq = Sequence().subtype(
        explicitTag=Tag(tagClassPrivate, tagFormatSimple, name_hex_int)
    )
    seq.setComponentByPosition(0, IA5String(name))
    seq.setComponentByPosition(1, value)
    return seq


def modifying_func(b, first=True):
    for i in range(len(b)):
        if str(b[i][0]) == "rosi":
            b[i][1][0][1] = plist["Manifest"]["OS"]["Digest"]
        elif str(b[i][0]) == "krnl":
            b[i][1][0][1] = plist["Manifest"]["KernelCache"]["Digest"]
        elif str(b[i][0]) == "dtre":
            b[i][1][0][1] = plist["Manifest"]["DeviceTree"]["Digest"]
        elif str(b[i][0]) == "trst":
            b[i][1][0][1] = plist["Manifest"]["StaticTrustCache"]["Digest"]
        elif str(b[i][0]) == "rtsc":
            b[i][1][0][1] = plist["Manifest"]["RestoreTrustCache"]["Digest"]
        elif str(b[i][0]) == "sepi":
            b[i][1][0][1] = plist["Manifest"]["SEP"]["Digest"]
        elif str(b[i][0]) == "rsep":
            b[i][1][0][1] = plist["Manifest"]["RestoreSEP"]["Digest"]
        # elif str(b[i][0]) == 'mtfw':
        #    b[i][1][0][1] = plist['Manifest']['Multitouch']['Digest']
        # elif str(b[i][0]) == 'rfta':
        #    # Corrupt this
        #    b[i][0] = 'atrf'
        # elif str(b[i][0]) == 'ftap':
        #    # Corrupt this
        #    b[i][0] = 'patf'
        elif str(b[i][0]) in ("rfta", "ftap", "rfts", "ftsp"):
            # b[i][1][0][1] = '5340b6a059bdb732e715e7bb1b292edcd45c2a8d1d07e6039d3f338d7c4428ab'
            b[i][0] = b[i][0][::-1]
        elif str(b[i][0]) == "MANP":
            manp = b[i][1]
            manp_length = len(manp)
            # if (not first):
            #    print(manp)
            for j in range(len(manp)):
                pass
                if str(manp[j][0]) == "CHIP":
                    # manp[j][1] = 0x1234
                    # manp[j][1] = 0x8015
                    # manp[j][1] = 0x8020
                    manp[j][1] = 0x8030
                if str(manp[j][0]) == "ECID" and first:
                    manp[j][1] = 0x1122334455667788
                if str(manp[j][0]) == "snon" and first:  # data_2422147c8_nonce
                    # manp[j][1] = b'\x00'*20
                    manp[j][1] = b"\xfe\xed\xfa\xce" * (20 // 4)
                    # manp[j][1] = b'\xef\xbe\xad\xde'*(20//4)
                # print(manp[j])

            # seq0 = create_seq('BORD', Integer(4))
            # manp.setComponentByPosition(5, seq0)
            # seq0 = create_seq('DGST', OctetString('a'*48))
            # manp.setComponentByPosition(manp_length+0, seq0)

            # seq1 = create_seq('EKEY', Boolean(True))
            # manp.setComponentByPosition(manp_length+0, seq1)

            # seq2 = create_seq('EPRO', Boolean(True))
            # manp.setComponentByPosition(manp_length+1, seq2)

            # seq3 = create_seq('ESEC', Boolean(True))
            # manp.setComponentByPosition(manp_length+2, seq3)

            ## data_2422147c8_nonce
            ##seq4 = create_seq('snon', OctetString('a'*20))
            # seq4 = create_seq('snon', OctetString(b'\xfe\xed\xfa\xce'*(20//4)))
            # manp.setComponentByPosition(manp_length+4, seq4)

            # seq4 = create_seq('AMNM', OctetString('a'*0x30))
            # seq4 = create_seq('AMNM', OctetString(b'\xfe\xed\xfa\xce'*(0x30//4)))
            seq4 = create_seq("AMNM", OctetString(b"\xde\xad\xbe\xef" * (0x30 // 4)))
            # manp.setComponentByPosition(manp_length+0, seq4)

            # print(manp.prettyPrint())
        # print(b[i])
        # print(type(b[i][1]))
        # print(b[i][1][0][0])
        # print(type(b[i][1][0][0]))
        # print(repr(b[i][1][0][1]))
        # print(type(b[i][1][0][1]))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(
            f"{sys.argv[0]} [model] [BuildManifest.plist] [ticket.shsh2] [root_ticket.der]"
        )
        exit(1)

    model = sys.argv[1].lower()
    fd = open(sys.argv[2], "rb")
    manifest = plistlib.load(fd)
    fd.close()

    plist = find_build_identity(manifest, model)

    if plist == None:
        print(f"Cannot find {model} in BuildManifest.plist")
        exit(1)

    fd = open(sys.argv[3], "rb")
    shsh = plistlib.load(fd)
    ticket = shsh["ApImg4Ticket"]
    fd.close()
    res = None
    res = decode(ticket, asn1Spec=APTicket())

    a = res[0]
    ###print(res)

    b = a["manb"][0]["payload"]
    modifying_func(b, True)

    c = a["cert"][0]["tbsCertificate"]["extensions"][4]["extnValue"]
    # print(type(c), repr(c))
    res = decode(c, asn1Spec=Set())[0]
    # print(res)
    ##print(res[0])
    # print(res)
    modifying_func(res, False)
    # print(res)
    a["cert"][0]["tbsCertificate"]["extensions"][4]["extnValue"] = encode(res)
    fd = open(sys.argv[4], "wb")
    print(a.prettyPrint())

    fd.write(encode(a))
    fd.close()
