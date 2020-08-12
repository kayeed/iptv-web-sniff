from sniff.web_live import web_live

from urllib.parse import urlparse, urlunparse
import requests
import json
import re
import os


class migu_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def __probe_high_resolution(self, link):

        orig_link = link
        if '1500/' in orig_link:
            link = orig_link.replace('/1500/','/3000/')
            if self.check_alive(link):
                return link
        elif '1200/' in orig_link:
            link = orig_link.replace('/1200/','/2500/')
            if self.check_alive(link):
                return link
        elif '350/' in orig_link:
            link = orig_link.replace('350/','3000/')
            if self.check_alive(link):
                return link
            link = orig_link.replace('350/','2500/')
            if self.check_alive(link):
                return link
            link = orig_link.replace('350/','2000/')
            if self.check_alive(link):
                return link
            link = orig_link.replace('350/','1000/')
            if self.check_alive(link):
                return link
        elif '51/' in orig_link:
            link = orig_link.replace('51/','57/')
            if self.check_alive(link):
                return link
        elif '50/' in orig_link:
            link = orig_link.replace('50/','57/')
            if self.check_alive(link):
                return link
            link = orig_link.replace('50/','75/')
            if self.check_alive(link):
                return link
            link = orig_link.replace('50/','150/')
            if self.check_alive(link):
                return link
        else:
            return orig_link

        return orig_link

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))
        liveurl = self.liveapi%(self.chname)
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(response.text)
            if info["code"] != "200":
                self.logger.error(info)
                return None
            link = info["body"]["urlInfo"]["url"]

            link = link.replace('/2018ocn/','/2018/ocn/')
            link = link.replace('ws450/','ws2000/')

            u = urlparse(link)
            result = u._replace(netloc='218.98.16.2:8080/live.hcs.cmvideo.cn')
            link = urlunparse(result)
            link = self.__probe_high_resolution(link)
            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        except ValueError:
            self.logger.error(response.text)
            return None
