from sniff.web_live import web_live, is_url

from urllib.parse import urlencode, urlparse, urlunparse, unquote
import subprocess
import requests
import random
import base64
import m3u8
import json
import time
import re
import os


class huya_live(web_live):

    def __init__(self, chname, request_info, extinfo, referer, logger):

        web_live.__init__(self, chname, request_info, extinfo, referer, logger)

    def __decode_link(self, link):

        i, b = link.split('?')
        r = i.split('/')
        s = re.sub(r'.(flv|m3u8)', '', r[-1])
        c = b.split('&', 3)
        c = [i for i in c if i != '']
        n = {i.split('=')[0]: i.split('=')[1] for i in c}
        fm = unquote(n['fm'])
        u = base64.b64decode(fm).decode('utf-8')
        p = u.split('_')[0]
        f = str(int(time.time() * 1e7 + 10000*random.random()))
        #f = str(int(time.time() * 1e7))
        l = n['wsTime']
        t = '0'
        h = '_'.join([p, t, s, f, l])
        m = self.md5(h)
        y = c[-1]
        link = "{}?wsSecret={}&wsTime={}&u={}&seqid={}&{}".format(i, m, l, t, f, y)

        return link

    def __mobile_player(self):
        liveurl = 'https://m.huya.com/' + self.chname
        header = {
                  'User-Agent': 'Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Mobile Safari/537.36'
                 }

        try:
            response = requests.get(liveurl, headers=header)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return None

        response.encoding = 'utf-8'
        find = re.findall(r'liveLineUrl = "([\s\S]*?)";', response.text)
        if find:
            link = "https:" + find[0].replace("\/", "/")
            return self.__decode_link(link)
        else:
            self.logger.error(response.text)
            return None

    def __desktop_player(self):
        liveurl = self.liveapi
        try:
            response = requests.get(liveurl, headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            self.logger.error(err)
            return

        response.encoding = 'utf-8'
        find = re.findall(r'"stream": "([a-zA-Z0-9+=/]+)"', response.text)
        if find:
            json_stream = find[0]
            data = json.loads(base64.b64decode(json_stream).decode())
            if data['status'] != 200:
                self.logger.error(data)
                return None

            stream_info = random.choice(data['data'][0]['gameStreamInfoList'])
            #stream_info = data['data'][0]['gameStreamInfoList'][0]
            sHlsUrl = stream_info['sHlsUrl']
            sStreamName = stream_info['sStreamName']
            sHlsUrlSuffix = stream_info['sHlsUrlSuffix']
            sHlsAntiCode = stream_info['sHlsAntiCode']
            hls_url = u'{}/{}.{}?{}&t=103'.format(sHlsUrl, sStreamName, sHlsUrlSuffix, sHlsAntiCode)
            hls_url = hls_url.replace("&amp;", "&")
            return self.__decode_link(hls_url)
        else:
            self.logger.error(response.text)
            return None

    def check_alive(self, uri):

        return False

    def sniff_stream(self):

        print("probe website %s ......"%(self.website))

        link = self.__mobile_player()
        #link = self.__desktop_player()
        if link:
            print("  {0: <20}{1:}".format(self.extinfo[4], link))
            channel = self.extinfo + [link] + [self.headers["Referer"] if self.referer == 1 else ""]
            self.link = link
            return channel
        else:
            self.logger.error("m3u8 link not found!")
            return None

    def sniff_m3u8_file(self, m3u8file):

        self.dump_custom_m3u8(self.link, m3u8file)
