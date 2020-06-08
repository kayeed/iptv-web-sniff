from sniff.web_live import web_live

import urllib.parse
import ipaddress
import requests
import random
import json
import time
import re
import os


class tvbnews_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def __web_player(self):

        ip_pool = [str(ip) for ip in ipaddress.IPv4Network('112.118.220.0/24')]
        ip = random.choice(ip_pool)
        token = "http://token.tvb.com/stream/live/hls/mobilehd_%s.smil?app=news&feed&client_ip=%s"%(self.chname, ip)
        #token = "http://token.tvb.com/stream/live/hls/mobilehd_%s.smil?app=news&feed&client_ip="%(self.chname)

        liveurl = "%s?token=%s"%(self.liveapi, urllib.parse.quote(token, safe=''))
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'

        try:
            info = json.loads(response.text)
            link = info["url"]
            return link
        except ValueError:
            self.logger.error(response.text)
            return None

    def __app_player(self):

        epoch = int(time.time()*1000)
        liveurl = "http://token.tvb.com/stream/live/hls/mobilehd_%s.smil?app=news&feed&time=%d"%(self.chname, epoch)
        self.headers['t'] = 'aea7cda047fc647bbde672a73c937f74'
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'

        try:
            info = json.loads(response.text)
            link = info["url"]
            return link
        except ValueError:
            self.logger.error(response.text)
            return None

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        link = self.__app_player()
        if link:
            try:
                response = requests.get(link, headers=self.headers, allow_redirects=False)
                response.raise_for_status()
            except requests.exceptions.RequestException as err:
                self.logger.error(err)
                return None

            if response.status_code == 302:
                link = response.headers["Location"]

            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        else:
            self.logger.error("m3u8 link not found!")
            return None

    def sniff_m3u8_file(self, m3u8file):

        self.dump_custom_m3u8(self.link, m3u8file)
