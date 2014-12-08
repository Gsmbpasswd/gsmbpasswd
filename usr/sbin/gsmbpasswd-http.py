#!/usr/bin/python
# -*- coding:utf-8 -*- 

# Needed in order to get settings from the configuration file
from ConfigParser import SafeConfigParser

# The main web.py framework, see http://webpy.org 
import web

CONF_FILE = u'/etc/gsmbpasswd/gsmbpasswd.conf'
config = SafeConfigParser()
config.read(CONF_FILE)

# Use either ip address or domain name to specify your samba server 
WEB_SERVER = config.get(u'WebServer', u'ServerName')
HTTPS_WEB_PAGE = u"https://" + WEB_SERVER

URLS = (
 u'/', u'Index',
)

class Index:
    def GET(self):
        raise web.seeother(HTTPS_WEB_PAGE)

if __name__=="__main__":
    app = web.application(URLS, globals())
    app.run() 
