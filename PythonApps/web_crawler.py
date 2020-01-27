'''
    author  : zerobits01
    created : 25-Jan-2020
    purpose : crawling a website and discovering
                it's structure(files and urls and paths)
'''

import requests as req
# import json
import argparse
import re


parser = argparse.ArgumentParser('''
    author : zerobits01
    gmail  : zerobits0101@gmail.com
    purpose: crawling a website and discovers the file structure
                and paths, urls
    team   : Paradox-Squad
''',formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-u','--url',help='url to crawl',type=str)

args = parser.parse_args()

class URLException(Exception):
    pass

class Crawler:

    def __init__(self,pathtosub,pathtocommons):
        self.sub_domains_test = []
        self.sub_domains = []
        self.common_test = []
        self.common = []
        self.pathtosub = '/root/Projects/Python/subdomaintest.txt' if pathtosub \
                                                                      is not None else pathtosub
        self.pathtocom = '/root/Projects/Python/subdomaintest.txt'if pathtocommons \
                                                                     is not None else pathtocommons
        with open(self.pathtosub, mode='r') as subdomains:
            for sub in subdomains:
                self.sub_domains_test.append(sub.strip())

        with open(self.pathtocom, mode='r') as commons:
            for com in commons:
                self.commons.append(com.strip())

    def __sendGetReq(self,url):
        try:
            if url is None :
                raise URLException
            if url.startswith('http'):
                url = args.url
            else:
                url = 'http://' + args.url
            resp = req.get(url)
        except req.exceptions.ConnectionError:
            print('[-] url not exist')
        except req.exceptions.InvalidURL:
            print('[-] url entered is not valid!!!!!!!!')
        except URLException:
            print('[-] didn\'t enter URL')
        else:
            return resp if resp.status_code == 200 else None

    def findSubDomains(self,url):
        for sub in self.sub_domains_test:
            if self.__sendGetReq(sub + '.' + url):
                self.sub_domains.append(sub + '.' + url)

    def findCommon(self,url) :
        for com in self.common_test:
            if self.__sendGetReq(url+'/'+com):
                self.commons.append(url+'/'+com)
        # we can use recursive mode in discovering new files and dirs
        # and pushing them in a list and discovering with depth


    def printSubs(self):
        for dom in self.sub_domains:
            print('[+] ' + dom)

    def printCommons(self):
        for com in self.commons:
            print('[+] %s' % (com))

    def extractor(self, url, base):
        try:
            html_resp = self.__sendGetReq(url).content
        except Exception:
            print('[-] something bad happened')
        else :
            links = re.findall(r'(?:href=")(.*?)"',html_resp)
            links_set = {link for link in links}
            for link in links_set :
                if not link.__contains__(base) :
                    links_set.add(base + '/' + link)
                    links_set.remove(link)
                    # we can use urlparse library
                    # but better versions check more options
                    # and do it more efficient
            return links_set
    def spider(self,url, depth): # crawler
        depth_list = []
        for i in range(depth):
            depth_list.append({})
        all_links = {url}
        # we can use multi-threading but in the simplest way we use for-loop
        depth_list[0] = self.extractor(url=url)
        all_links = all_links.union(depth_list[0])
        for i in range(depth):
            for sub_url in depth_list[i]:
                if sub_url not in all_links:
                    all_links.add(sub_url)
                    depth_list[i+1] = self.extractor(sub_url)

        return {u for u in all_links}


# the point is that we have to create word-lists for different attacks
# also the speed depends on using better algorithms and using async or threading
# we can also design GUI with Qt5