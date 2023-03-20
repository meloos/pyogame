import json
import base64
from datetime import datetime
from random import randint
from urllib.parse import quote

class Fingerprint:
  def __init__(self, user_agent) -> None:
    self.obj = {
        "v": 8,
        "tz": "Europe/Warsaw",
        "dnt": False,  # do not track
        "product": "Gecko",
        "osType": "Linux",
        "app": "Firefox",
        "vendor": "",
        "mem": 0,
        "con": 2,
        "lang": "pl-PL",
        "plugins": "f473d473013d58cee78732e974dd4af2e8d0105449c384658cbf1505e40ede50",
        "gpu": "Mesa/X.org,Generic Renderer",
        "fonts": "67574c80452bcc244b31e19a66a5f4768b48be6d88dfc462d5fa7d8570ed87da",
        "audioC": "c6a7feda4a58521c20f9ffd946a0ce3edfac57a54e35e73857e710c85a9e4415",
        "width": 1900,
        "height": 1000,
        "depth": 24,
        "lStore": True,
        "sStore": True,
        "video": "1f03b77fda33742261bea0d27e6423bf22d2bf57febc53ae75b962f6e523cc02",
        "audio": "c76e22cc6aa9f5a659891983b77cd085a3634dd6f6938827ab5a4c6c61a628e5",
        "media": "d15bbda6b8af6297ea17f2fb6a724d3bacde9b2e1285a951ee148e4cd5cc452c",
        "permissions": "86beeaf2f319e30b7dfedc65ccb902a989a210ffb3d4648c80bd0921aa0a2932",
        "audioFP": 35.738334245979786,
        "webglFP": "7d6f8162c7c6be70d191585fd163f34dbc404a8b4f6fcad4d2e660c7b4e4b694",
        "canvasFP": 732998116,
        "creation": self.jsISOTime(datetime.utcnow()),
        "uuid": "ajs3innzou3hulixyriljvj89by",
        "d": randint(300, 500),  # how long it took to collect data
        "osVersion": None,
        "vector": self.getVector(datetime.now()),
        "userAgent": user_agent,
        "serverTimeInMS": self.jsISOTime(datetime.utcnow().replace(microsecond=1)),
        "request": None,
    }

    enObj = []
    for k, v in self.obj.items():
        enObj.append(v)
    enObj = json.dumps(enObj, separators=(",", ":"))

    self.encrypted = self.encrypt(enObj)

  def encodeURIComponent(self, s):
    return quote(s, safe="!~*'()")

  def pseudoB64(self, s):
    lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    lenMod3 = len(s) % 3
    out = ""
    for i in range(0, len(s), 3):
      c1 = ord(s[i])
      c2 = ord(s[i + 1]) if i + 1 < len(s) else 0
      c3 = ord(s[i + 2]) if i + 2 < len(s) else 0
      t = c1 << 16 | c2 << 8 | c3
      out += lut[t >> 18 & 63] + lut[t >> 12 & 63] + lut[t >> 6 & 63] + lut[t & 63]
    return out[:lenMod3 - 3] if lenMod3 > 0 else out

  def jsISOTime(self, d):
    return d.isoformat()[:23] + "Z"
  
  def getVector(self, d):
    v = "l)i:Pa*muI!S]A%93uw=EWw{c\\/*Twy)|{ya+9!wIc}E^J8D1-0.t'eQ;eS)p\\r<[@4c1UOVVgRNmL^v8|Nq?$mY8u4p7FTPFL*F"
    dv = (v + " " + str(int(d.timestamp() * 1000))).encode("utf-8")
    return base64.b64encode(dv).decode("utf-8")
  
  def encrypt(self, s):
    s = self.encodeURIComponent(s)
    out = s[0]
    for i in range(1, len(s)):
      out += chr((ord(out[i - 1]) + ord(s[i])) % 256)
    return self.pseudoB64(out)