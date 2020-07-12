from sniff.web_live import web_live

from urllib.parse import urlparse, urlunparse
import requests
import json
import time
import re
import os


class ifeng_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        liveurl = self.liveapi
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'

        try:
            info = json.loads(response.text)
            for channel in info:
                if channel["title"] == self.chname:
                    liveurl = channel["live_url_fhd"]
                    u = urlparse(liveurl)
                    livepath = u.path.split(".")[0]

                    epoch = "%x"%int(time.time()+1800)
                    input = "obb9Lxyv5C"+livepath+epoch
                    link = "%s?txSecret=%s&txTime=%s"%(liveurl, self.md5(input), epoch)
                    link = self.http_redirect(link)
                    print("  {0: <20}{1:}".format(self.extinfo[4], link))
                    channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
                    self.link = link
                    return channel

            self.logger.error(info)
            return None
        except (ValueError, KeyError) as err:
            self.logger.error("%s - %s"%(err,response.text))
            return None

    def check_alive(self, uri):

        return False

    def sniff_m3u8_file(self, m3u8file):

        pass
