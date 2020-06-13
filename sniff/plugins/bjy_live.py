from sniff.web_live import web_live

from urllib.parse import urlencode

import subprocess
import requests
import json
import time
import re
import os


class bjy_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        params = {'app_version': '1.0.0',
                  'assetID': self.chname,
                  'clientid': '1',
                  'device_id': "1B:DD:71:AC:08:60",
                  'ip': '192.168.0.1',
                  'modules': 'programplay:1',
                  'playType': '2',
                  'resourceCode': self.chname,
                  'siteid': '10001',
                  'system_name': 'android',
                  'type': 'android'
                  }
        epoch = "%d"%int(time.time()*1000)
        print(urlencode(params))
        sign = self.md5(self.md5(urlencode(params)) + '7ad794e167910229dc2dcec45749b9da' + epoch);

        liveurl = self.liveapi%(sign, epoch, self.chname, self.chname)
        print(liveurl)
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None
        response.encoding = 'utf-8'
        try:
            info = json.loads(response.text)
            link = info['data']['programplay']['bitPlayUrlList'][1]['url']
            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        except (ValueError, KeyError):
            self.logger.error(response.text)
            return None
