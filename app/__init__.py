from flask import Flask
#from flask.ext.cache import Cache

app = Flask(__name__)
#cache = Cache(app,config={'CACHE_TYPE': 'filesystem','CACHE_DIR':'/tmp'})

from flask import render_template
from app import app
import os, sys, glob, datetime, re, mmap, time
from operator import itemgetter
from nagios import NagiosDashboard

@app.route('/')
@app.route('/index')
#@cache.cached(timeout=50)
def index():
	infolist = []
	alertlist = []
	warninglist = []
	unknownlist = []
	pendinglist = []
	infolistdown = []
	alertlistdown = []
	warninglistdown = []
	unknownlistdown = []
	pendinglistdown = []
	oklistdown = []
	length = 0
	try:
		nagios = NagiosDashboard.NagiosParse()
		nagios.setdebug(False)
		status = nagios.readconfig('/var/nagiosramdisk/status.dat','=')
		services = nagios.readcfg('/usr/local/nagios/etc/services/')
		hosts = nagios.readcfg('/usr/local/nagios/etc/hosts/')
		hostgroups = nagios.readconfig('/usr/local/nagios/etc/hostgroups.cfg',"\t")
		nagiosurl = "https://nagios01.example.com"
		nagiosdashboard = "http://nagios01.example.com:8082"

		rendering = NagiosDashboard.NagiosRender(status, hosts, services, hostgroups)
		# Set Updates as a info and not critical or warning
		rendering.setinfolist(['Yum Updates','APT Updates'])
		# Set CPU stats as a warning and not critical
		rendering.setwarnlist(['CPU Stats'])
		infolist , alertlist , warninglist , unknownlist , pendinglst , infolistdown , alertlistdown , warninglistdown , unknownlistdown , pendinglistdown, oklistdown = rendering.render()
		length = len(alertlist)+len(warninglist)+len(unknownlist)
	except ValueError as err:
		print (err.args) 
	except:
		print "bummer"
	return render_template("index.html", title = 'Home', infolist=infolist , alertlist=alertlist , warninglist=warninglist , unknownlist=unknownlist , pendinglist=pendinglist , infolistdown=infolistdown , alertlistdown=alertlistdown , warninglistdown=warninglistdown , unknownlistdown=unknownlistdown , pendinglistdown=pendinglistdown, oklistdown=oklistdown, length=length, loopindex=1, nagiosurl=nagiosurl, nagiosdashboard=nagiosdashboard)

if __name__ == '__main__':
    app.run()

