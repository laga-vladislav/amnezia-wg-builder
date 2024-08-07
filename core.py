import json

from PyQt6.QtCore import *


def unpack(s):
    ba = QByteArray(s[6:].encode())
    ba = QByteArray.fromBase64(ba,
                               QByteArray.Base64Option.Base64UrlEncoding | QByteArray.Base64Option.OmitTrailingEquals)
    return str(qUncompress(ba), 'utf-8')


def pack(s):
    try:
        json.loads(s)
    except Exception as e:
        return 'ERROR: ' + str(e)
    ba = qCompress(QByteArray(s.encode()))
    ba = ba.toBase64(QByteArray.Base64Option.Base64UrlEncoding | QByteArray.Base64Option.OmitTrailingEquals)
    return 'vpn://' + str(ba, 'utf-8')


if __name__ == '__main__':
    print("Everything is fine, just execute program.py file")
