from sniff.web_live import web_live, is_url

from urllib.parse import urlencode
import subprocess
import requests
import m3u8
import json
import time
import re
import os


class woniu_live(web_live):


    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        liveurl = self.liveapi%self.chname
        sign = self.md5("c=1&channelId=%s&type=3&v=109&key=ae07e6df6a17c986cf11d36e3311a0dd"%self.chname)
        headers = {
                "User-Agent": "okhttp/3.14.4",
                "c": "1",
                "v": "109",
                "sign" :sign
               }
        try:
            response = requests.get(liveurl, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(response.text)
            link = info['d']['playAddress']
            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        except (ValueError, KeyError) as err:
            self.logger.error("%s - %s"%(err, response.text))
            self.logger.error(response.text)
            return None

    def sniff_m3u8_file(self, m3u8file):

        pass
