from sniff.utils.iqiyi_util import get_random_str, get_macid, cmd5x_iqiyi3 as cmd5x
from sniff.web_live import web_live, is_url

from urllib.parse import urlencode
import subprocess
import requests
import m3u8
import json
import time
import re
import os


class iqiyi_video(web_live):


    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def check_alive(self, uri):

        return False

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
        m = re.search("\"tvId\":(\d*),\"vid\":\"([A-Za-z0-9_-]*)\"", response.text)
        if m:
            tvid = m.group(1)
            vid  = m.group(2)
        else:
            self.logger.error("tivd and vid not found!")
            return None

        tm = int(time.time() * 1000)
        host = 'http://cache.video.qiyi.com'
        params = {
            'tvid': tvid,
            'vid': vid,
            'v': 0,
            'qypid': '{}_12'.format(tvid),
            'src': '01012001010000000000',
            't': tm,
            'k_tag': 1,
            'k_uid': get_macid(),
            'rs': 1,
        }
        src = '/vps?{}'.format(urlencode(params))
        vf = self.md5(src+'1j2k2k3l3l4m4m5n5n6o6o7p7p8q8q9r')

        liveurl = '{}{}&vf={}'.format(host, src, vf)
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None

        response.encoding = 'utf-8'
        info = json.loads(response.text)
        try:
            info = json.loads(response.text)
            if info["code"] != "A00000":
                self.logger.error(info)
                return None
            url_prefix = info["data"]["vp"]["du"]
            for stream in info["data"]["vp"]["tkl"][0]["vs"]:
                if stream["scrsz"] == "3840x2152" or stream["scrsz"] == "1920x1080":
                    link = url_prefix + stream["fs"][0]["l"]
            if link:
                liveurl = link
                try:
                    response = requests.get(liveurl, headers=self.headers)
                    response.raise_for_status()
                except requests.exceptions.RequestException as err:
                    self.logger.error(err)
                    return None

                response.encoding = 'utf-8'
                info = json.loads(response.text)
                link = info['l']
                print("  {0: <20}{1:}".format(self.extinfo[4], link))
                channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
                self.link = link
                return channel
            self.logger.error(info)
            return None
        except ValueError:
            self.logger.error(response.text)
            return None

    def sniff_m3u8_file(self, m3u8file):

        pass
