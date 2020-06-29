from sniff.web_live import web_live

from urllib.parse import urlencode
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from base64 import b64decode, b64encode

import subprocess
import requests
import hashlib
import hmac
import json
import time
import re
import os


class gdtv_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def __new_player(self):

        liveurl = self.liveapi%(self.chname)

        epoch = "%d"%int(time.time()*1000)
        key = '89541443007807288657755311869534'
        secret = 'dfkcY1c3sfuw0Cii9DWjOUO3iQy2hqlDxyvDXd1oVMxwYAJSgeB6phO8eW1dfuwX'
        message = "GET\n" + liveurl + "\n" + epoch + "\n"
        data = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
        signature = b64encode(data)
        headers = {
            "x-itouchtv-ca-key": key,
            "x-itouchtv-ca-signature": signature,
            "x-itouchtv-ca-timestamp": epoch,
            "x-itouchtv-client": "WEB_PC",
            "x-itouchtv-device-id": "WEB_6718dd60-b79e-11ea-a943-bd094ad2a8c4",
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0"}
        try:
            response = requests.get(liveurl, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(json.loads(response.text)['playUrl'])
            link = info['hd']
            return link
        except (ValueError, KeyError):
            self.logger.error(response.text)
            return None

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))
        link = self.__new_player()
        if link:
            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        else:
            self.logger.error("m3u8 link not found!")
            return None
