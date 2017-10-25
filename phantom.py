"""module needed to perform whois queries"""
import pythonwhois
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
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from xvfbwrapper import Xvfb

parser = argparse.ArgumentParser(description='Add a domain to scan')
parser.add_argument('-d', '--domain', help='domain to scan')

service_args = [
    '--proxy=127.0.0.1:8080',
    '--proxy-type=https',
    ]

class BrowserSession(object):
    """Creates a new selenium + proxy session"""
    def __init__(self):
	self.vdisplay = Xvfb()
	self.vdisplay.start()
        self.server = Server("/home/pablo/code/ajax/browsermob-proxy-2.1.4/bin/browsermob-proxy")
        self.server.start()
        self.proxy = self.server.create_proxy()
	self.proxy_address = "--proxy=127.0.0.1:%s" % self.proxy.port
	self.service_args = [ self.proxy_address, '--ignore-ssl-errors=yes', ] 
        self.driver = webdriver.PhantomJS(service_args=self.service_args)
	self.driver.set_window_size(1120, 550)
        #self.driver = webdriver.Chrome(chrome_options=self.profile)
        self.options = {"captureHeaders": True}
        self.proxy.new_har("fox",self.options)

    def close(self):
        self.driver.quit()
	self.proxy.close()
        self.server.stop()
	self.vdisplay.stop()

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
            data = self.proxy.har
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

def readData():
    f = open ('test.har', 'r')
    try: 
        x = json.loads(f.read())
        urls = set()
        for i in x['log']['entries']:
            parsed_uri = urlparse(i['request']['url'])
            tld = tldextract.extract(parsed_uri.netloc)
            urls.add(tld.domain + '.' + tld.suffix)
        return sorted(urls)
    finally:
        f.close()

args = parser.parse_args()
print ("Starting with " + args.domain)
b = BrowserSession()
print "start browsing"
b.browse("http://" + args.domain)
print "browsing finished"
b.close()
x = readData()
for i in x:
    print "reading data"
    print i
    d = Domain(i)
    d.query()
    if not d.exists():
        print (args.domain + " - " + i + " doesn't exist")
