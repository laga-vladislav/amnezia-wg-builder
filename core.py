import json
from PyQt6.QtCore import *


def pack(s):
    try:
        json.loads(s)
    except Exception as e:
        return 'ERROR: ' + str(e)
    ba = qCompress(QByteArray(s.encode()))
    ba = ba.toBase64(QByteArray.Base64Option.Base64UrlEncoding | QByteArray.Base64Option.OmitTrailingEquals)
    return 'vpn://' + str(ba, 'utf-8')
