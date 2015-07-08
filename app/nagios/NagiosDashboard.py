#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# Kim G. Nielsen wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Kim G. Nielsen
# ----------------------------------------------------------------------------
#
import os, sys, glob, re, mmap, time, datetime

class NagiosParse:
	''' Help parsing nagios status and config files '''
	debug = False

        def __init__(self):
        	self.debug = False
		self.funcre = re.compile('([a-zA-Z\ ]+) {')
		self.septabre = re.compile(r'(.*)\t(.*)')

	def setdebug(self, flag):
		self.debug = flag

	def validate(self, cat, obj):

		# Only add hoststatus if there is an state other than ok
		#if cat=='hoststatus' and obj['current_state']=='0':
		#	return False	

		# Only add servicestatus if there is an state other than ok
		#if cat=='servicestatus' and obj['current_state']=='0':
		#	return False	

		# Only add valid object
		if cat=='define host' and obj['register']!='1':
			return False	
		if cat=='define service' and obj['register']!='1':
			return False	

		return True

	def readconfig(self, file, seperator='='):
		''' Read all status values into categorized arrays'''

		self.datfile = file
		self.nagiosstate = {}

                if os.path.exists(self.datfile) == False:
                        raise ValueError, 'unable to open file: ' + self.datfile

		try:
			hoststatus = False
			inside = False
			index = ''

			tmp = {}

                	with open(self.datfile, "r") as f:
                        	map = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
                        	for line in iter(map.readline, ""):
					
					m = self.funcre.match(line)
					if m:
						# Mark that we are inside a configuration and set the index
						index = m.group(1).strip()
						if self.debug:
							print "configuration match on [%s]" %(index)
						inside = True

					elif line.strip()[:1] == '}':
						# We just left a configuration so we need to store it
						if self.nagiosstate.has_key(index):
							if self.debug:
								print "Adding index [%s]" % (index)
								print tmp
							if self.validate(index, tmp):
								self.nagiosstate[ index ].append( tmp )
								
						else:
							if self.debug:
								print "Creating index [%s]" % (index)
								print tmp
							if self.validate(index, tmp):
								self.nagiosstate[ index ] = [ tmp ]

						inside = False
						tmp = {}

					# if inside a definition then we store in key, value pairs
					if inside:
						if seperator=='=':
							first = line.find("=")
							if first!=-1:
								key = line[:first].strip()
								value = line[first+1:].strip()
								if self.debug:
									print "key:" + key + " value:" + value
								tmp[key] = value
						elif seperator=="\t":
							m = self.septabre.match(line.strip())
							if m:
								key =  m.group(1).strip()
								value =  m.group(2).strip()
								if self.debug:
									print "key:" + key + " value:" + value
								tmp[key] = value

                                                continue

			if self.debug:
				for key in self.nagiosstate:
					print 'index: ' + key
					for v in self.nagiosstate[key]:
						print "\t["
						print v
						print "\t]"

		except IOError:
			raise ValueError, 'Unable to read file: ' + self.datfile
		except KeyboardInterrupt:
			raise ValueError, 'Break by keyboard.'
		else:
			f.close()

		return self.nagiosstate

	def readcfg(self, dir):
		''' Read a directory with config files '''
		cfgs = {}
		for file in glob.glob(dir + '*.cfg'):
			tmp=self.readconfig(file, "\t")
			''' and merge all finding '''
			for index in tmp:
				for v in tmp[index]:
					if cfgs.has_key(index):
						cfgs[index].append( v )
					else:
						cfgs[index] = [ v ]
		return cfgs

class NagiosRender():

        def __init__(self, statuslist, hostlist, servicelist, hostgrouplist):
		self.debug = False
		self.infolist = []
		self.warnlist = []
		self.alertlist = []
		self.status = statuslist
		self.hosts = hostlist
		self.services = servicelist
		self.hostgroups = hostgrouplist
		self.hStatus = ['HOSTUP','HOSTDOWN','HOSTUNREACHABLE','HOSTPENDING','INFO']
		self.sStatus = ['OK','WARNING','CRITICAL','UNKNOWN','PENDING','INFO']
		self.now = int(time.time())
		# Percent of current_attempt / max_attempts * 100 that should be shown
		self.pct = 100.0

	''' Functions to lower or raise alerts, warnings or info. Nagios does not have the info list so we will add one '''
	def setinfolist(self, list):
		self.infolist = list
	def setwarnlist(self, list):
		self.warnlist = list
	def setalertlist(self, list):
		self.alertlist = list
	def setpct(self, pct):
		self.pct = float(pct)
	def readableduration(self, duration):

		then = self.now - int(duration)

		d = divmod(then,86400)  # days
		h = divmod(d[1],3600)  # hours
		m = divmod(h[1],60)  # minutes
		s = m[1]

		days = ''
		if d[0] > 0:
			days="%d day" % (d[0])
			if d[0] > 1:
				days+="s"

		hour = ''
		if h[0] > 0:
			hour="%d hour" % (h[0])
			if h[0] > 1:
				hour+="s"

        	min = ''
       		if m[0] > 0:
               		min="%d minute" % (m[0])
               		if m[0] > 1:
                       		min+="s"

		sec = ''
		if d[0]==0 and h[0]==0 and m[0]==0:
			sec = "%d sec" % (s)
			if s > 1:
                       		sec+="s"
		
		ret = []
		if days is not '':
			ret.append(days)
		if hour is not '':
			ret.append(hour)
		if min is not '':
			ret.append(min)
		if sec is not '':
			ret.append(sec)
		retstr = ", ".join(ret)

        	return retstr

	def render(self):

		# IF no hostgroup is defined we call it None
		tmp = {'hostgroup_name': 'None', 'alias': 'None'}
		hosts = {}
		self.hostgroups['define hostgroup'].append(tmp)

		# Sort list of hostgroups and add references to hosts
		sortedgroup = sorted(self.hostgroups['define hostgroup'], key=lambda k: k['alias'])

		hostlookup = {}

		for g in sortedgroup:
			group=g['hostgroup_name']
			for h in self.hosts['define host']:
	
				hostgroup='None'	
				if h.has_key('hostgroups'):
					hostgroup=h['hostgroups']

				if group==hostgroup:
					if hosts.has_key(g['hostgroup_name']):				
						hosts[group].append(h['host_name'])
					else:
						hosts[group]=[h['host_name']]
				hostlookup[h['host_name']] = h

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

		for g in sortedgroup:
			if hosts.has_key(g['hostgroup_name']):
				sortedhosts = sorted(hosts[g['hostgroup_name']], key=str.lower)
				for h in sortedhosts:
			
					host_address = ''
					if hostlookup[h].has_key('address'):
						host_address = hostlookup[h]['address']

					host_alias = ''
					if hostlookup[h].has_key('alias'):
						host_alias = hostlookup[h]['alias']

					hosticon = ''
					if hostlookup[h].has_key('icon_image'):
						hosticon = hostlookup[h]['icon_image']

					# Host checks
					hostfilter = filter(lambda service: service['host_name'] == h and service['current_state'] is not '0', self.status['hoststatus'])
					if hostfilter:
						for s in hostfilter:
							# current_attempt is always 1 on host checks :(
							#pct = float((float(s['current_attempt'])/float(s['max_attempts']))*100.0)
							#if pct >= self.pct:
							#	continue

							s['service_description'] = ''
							s['hostgroup'] = g['hostgroup_name']
							s['current_text'] = self.hStatus[int(s['current_state'])]
							s['host_address'] = host_address
							s['host_alias'] = host_alias
							s['hosticon'] = hosticon
							s['service_description'] = 'Hostcheck'
							
							s['duration_text'] = 'N/A'
							if s.has_key('last_state_change') and s['last_state_change'] is not '0':
								s['duration_text'] = self.readableduration(s['last_state_change'])

							down = {}
							if self.status.has_key('hostdowntime'):
								down = filter(lambda service: service['host_name'] == h and service['is_in_effect'] is '1', self.status['hostdowntime'])

							if down:
								s['downcomment'] = ''
								if down[0].has_key('comment'):							
									s['downcomment'] = down[0]['comment'].decode('utf-8')

								s['downauthor'] = ''
								if down[0].has_key('author'):							
									s['downauthor'] = down[0]['author'].decode('utf-8')

								s['enddown'] = ''
								if down[0].has_key('end_time'):							
									s['enddown'] = datetime.datetime.fromtimestamp(float(down[0]['end_time'])).strftime('%Y-%m-%d %H:%M:%S')
	
								if s['current_state'] is '4':
									infolistdown.append(s)	
								elif s['current_state'] is '3':
									pendinglistdown.append(s)
								elif s['current_state'] is '2':
									s['current_state'] = '2'
									unknownlistdown.append(s)
								elif s['current_state'] is '1':
									s['current_state'] = '2'
									alertlistdown.append(s)
								elif s['current_state'] is '0':
									oklistdown.append(s)
							else:
								if s['current_state'] is '4':
									infolist.append(s)	
								elif s['current_state'] is '3':
									pendinglist.append(s)
								elif s['current_state'] is '2':
									s['current_state'] = '2'
									unknownlist.append(s)
								elif s['current_state'] is '1':
									s['current_state'] = '2'
									alertlist.append(s)

					# Service checks
					servicefilter = sorted(filter(lambda service: service['host_name'] == h, self.status['servicestatus']), key=lambda k: k['service_description'])
					for s in servicefilter:
						pct = float((float(s['current_attempt'])/float(s['max_attempts']))*100.0)
						#print "%0.2f >= %0.2f" % (pct, self.pct)
						if pct < self.pct:
							continue

						# Rewrite info/warning/alerts
						if s['service_description'] in self.infolist:
							s['current_state'] = '5'
						elif s['service_description'] in self.warnlist:
							s['current_state'] = '1'
						elif s['service_description'] in self.alertlist:
							s['current_state'] = '2'
					
						s['hostgroup'] = g['hostgroup_name']
						s['current_text'] = self.sStatus[int(s['current_state'])]
						s['host_address'] = host_address
						s['host_alias'] = host_alias
						s['hosticon'] = hosticon
						s['duration_text'] = 'N/A'
						if s.has_key('last_state_change') and s['last_state_change'] is not '0':
							s['duration_text'] = self.readableduration(s['last_state_change'])

						# Check if the service is down	
						down = {}
						if self.status.has_key('servicedowntime'):
							down = filter(lambda service: service['host_name'] == h and service['service_description']==s['service_description'] and service['is_in_effect'] is '1', self.status['servicedowntime'])
						if down:
							s['downcomment'] = ''
							if down[0].has_key('comment'):							
								s['downcomment'] = down[0]['comment']

							s['downauthor'] = ''
							if down[0].has_key('author'):							
								s['downauthor'] = down[0]['author']

							s['enddown'] = ''
							if down[0].has_key('end_time'):							
								s['enddown'] = datetime.datetime.fromtimestamp(float(down[0]['end_time'])).strftime('%Y-%m-%d %H:%M:%S')

							if s['current_state'] is '5':
								infolistdown.append(s)	
							elif s['current_state'] is '4':
								pendinglistdown.append(s)
							elif s['current_state'] is '3':
								unknownlistdown.append(s)
							elif s['current_state'] is '2':
								alertlistdown.append(s)
							elif s['current_state'] is '1':
								warninglistdown.append(s)
							elif s['current_state'] is '0':
								oklistdown.append(s)
						else:
							if s['current_state'] is '5':
								infolist.append(s)	
							elif s['current_state'] is '4':
								pendinglist.append(s)
							elif s['current_state'] is '3':
								unknownlist.append(s)
							elif s['current_state'] is '2':
								alertlist.append(s)
							elif s['current_state'] is '1':
								warninglist.append(s)
		return ( infolist , alertlist , warninglist , unknownlist , pendinglist , infolistdown , alertlistdown , warninglistdown , unknownlistdown , pendinglistdown, oklistdown )
	
if __name__ == '__main__':
	try:
		nagios = NagiosParse()
		nagios.setdebug(False)
		status = nagios.readconfig('/var/nagiosramdisk/status.dat','=')
		services = nagios.readcfg('/usr/local/nagios/etc/services/')
		hosts = nagios.readcfg('/usr/local/nagios/etc/hosts/')
		hostgroups = nagios.readconfig('/usr/local/nagios/etc/hostgroups.cfg',"\t")

		rendering = NagiosRender(status, hosts, services, hostgroups)
		# Set Updates as a info and not critical or warning
		rendering.setinfolist(['Yum Updates','APT Updates'])
		# Set CPU stats as a warning and not critical
		rendering.setwarnlist(['CPU Stats'])
		# Only show services that have failed more than 20%
		rendering.setpct(50.0)
		rendering.render()

	except ValueError as err:
		print (err.args)

