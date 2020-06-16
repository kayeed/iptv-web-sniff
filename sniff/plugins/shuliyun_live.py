from sniff.web_live import web_live, is_url

from urllib.parse import urlencode
import subprocess
import requests
import m3u8
import json
import time
import re
import os


class shuliyun_live(web_live):


    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        liveurl = self.liveapi
        data = {
                "deviceType":"yuj",
                "deviceno":"CCB5FA96365563E36E514945070588FD5",
                "role":"guest"
                }
        try:
            response = requests.post(liveurl, json=data, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(response.text)
            accesstoken = info["accessToken"]
        except ValueError:
            self.logger.error(response.text)
            return None

        liveurl = "http://slave.shuliyun.com:13160/media/channel/get_info?chnlid=%s&verifycode=14183&accesstoken=%s"%(self.chname, accesstoken)
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(response.text)
            playtoken = info["play_token"]
            liveurl = info["livetv_url"][0]
        except ValueError:
            self.logger.error(response.text)
            return None

       	params = {
                  'playtype': 'live',
                  'protocol': 'hls',
                  'accesstoken': accesstoken,
                  'playtoken': playtoken
                 } 
        link = "%s?%s&programid=%s.m3u8"%(liveurl, urlencode(params), self.chname)
        print("  {0: <20}{1:}".format(self.extinfo[4], link))
        channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
        self.link = link
        return channel

    def sniff_m3u8_file(self, m3u8file):

        pass
