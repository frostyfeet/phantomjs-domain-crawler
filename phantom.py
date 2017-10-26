"""module needed to perform whois queries"""
import pythonwhois
import sys
import os
from browsermobproxy import Server
from selenium import webdriver
import selenium.webdriver.support.ui as ui
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from urlparse import urlparse
import tldextract
import json
import time
import argparse
import operator
import pprint
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
#from xvfbwrapper import Xvfb

parser = argparse.ArgumentParser(description='Add a file to scan')
parser.add_argument('-r', '--read', help='file with domains')

server = Server("/Users/p/Downloads/browsermob-proxy-2.1.4/bin/browsermob-proxy")
server.start()
proxy = server.create_proxy()
options = {"captureHeaders": True}
proxy.new_har("fox",options)

class BrowserSession(object):
    """Creates a new selenium + proxy session"""
    def __init__(self):
        #self.vdisplay = Xvfb()
        #self.vdisplay.start()
        self.proxy_address = "--proxy=127.0.0.1:%s" % proxy.port
        self.service_args = [ self.proxy_address, '--ignore-ssl-errors=yes', ] 
        self.driver = webdriver.PhantomJS(service_args=self.service_args)
        self.driver.set_window_size(1120, 550)
        #self.driver = webdriver.Chrome(chrome_options=self.profile)
        
    def close(self):
        self.driver.quit()

    def clickOn(self, csstag):
        try:
            self.driver.find_element_by_css_selector(csstag).click()
            print ("clicked on item and sleeping 10")
            time.sleep(10)
            print ("done waiting")
            self.driver.get("https://hootsuite.com/dashboard")
            return True
        except Exception as e:
            print ("Couldnt click" + str(e))
            return False
    
    def browse(self,url):
        try:
            val = URLValidator
            val (url)
            self.driver.get(url)
            data = proxy.har
            fw = open('test.har', 'w')
            fw.write(json.dumps(data))
        except ValidationError, e:
            print e

class Domain(object):
    """Defines the domain object and attributes"""

    def __init__(self, url):
        self.domain = url
    def query(self):
        try:
            self.info = pythonwhois.get_whois(self.domain)
        except:
            return False
    def exists(self):
        """returns true if domain exists"""
        try:
            if 'expiration_date' in self.info or 'registrar' in self.info:
                return True
            else:
                return False
        except:
            return False
    def getregistar(self):
        """return whatever"""
        try:
            if 'registrar' in self.info:
                return self.info['registrar']
            else:
                return None
        except:
            return None
    def getexpiration(self):
        """returns expiration date"""
        try:
            if 'expiration_date' in self.info:
                return self.info['expiration_date']
            else:
                return None
        except:
            return None

def readData(domain):
    print ("Getting URLs for: " + domain)
    f = open ('test.har', 'r')
    try: 
        x = json.loads(f.read())
        urls = set()
        for i in range(len(x['log']['entries'])):
            for j in range(len(x['log']['entries'][i]['request']['headers'])):
                if str(x['log']['entries'][i]['request']['headers'][j]['name']) == 'Referer':
                    tld_ref = tldextract.extract(urlparse(x['log']['entries'][i]['request']['headers'][j]['value']).netloc)
                    referer = tld_ref.domain + '.' + tld_ref.suffix
                    if (domain == referer):
                        parsed_uri = urlparse(x['log']['entries'][i]['request']['url'])
                        tld = tldextract.extract(parsed_uri.netloc)
                        urls.add(tld.domain + '.' + tld.suffix)
        return sorted(urls)
    finally:
        f.close()

def main(argv):
    args = parser.parse_args()
    print ("Reading file: " + args.read)
    with open (args.read, 'r') as f:
        for line in f:
            b = BrowserSession()
            print "start browsing"
            b.browse("http://" + line.strip())
            print "browsing finished"
            b.close()
    with open (args.read, 'r') as f:
        for line in f:
            x = readData(line.strip())
            for i in x:
                d = Domain(i)
                d.query()
                if not d.exists():
                    print (line.strip() + " - " + i + " - Domain not registered")
                else:
                    print (line.strip() + " - " + i )

if __name__ == "__main__":
    main(sys.argv)

os.system('kill -9 $(ps -e | grep browsermob | awk "{print $1}") ')