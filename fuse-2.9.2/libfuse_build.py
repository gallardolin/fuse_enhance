#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import os
import sys
import commands
import time, datetime


usage =  'python libfuse_build.py' 

def error_log(string):
	"""
		Create the log file to record errors
	"""
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	
	file = open("./libfuse-build-err.log", "a")
	file.write("[%s] %s\n\n" %(st, string) )
	file.close()

def configure_set():
	"""
		To configure and make clean in this function.
		
		Return 0 if all processes are successful.
	"""
	print "[libfuse] start to make clean and configure."
	
	
	if os.path.exists('./Makefile'):
		(status, output) = commands.getstatusoutput('make clean')
		if status != 0 :
			error_log("== output of make clean ==\n" + output)
			print "make clean failed "
			return -2
	
	if not os.path.exists('./libfuse_build'):
		os.makedirs('./libfuse_build/usr')
					
	configure_command = "chmod a+x configure && ./configure --exec-prefix=%s/libfuse_build/usr" % os.getcwd()
	(status, output) = commands.getstatusoutput(configure_command)
	if status ==0:
		print "configure successfully set"
		return 0	
	else:
		error_log("== output of configure ==\n" + output)
		print "configure unsuccessfully set"
		return -1	

def make_install():
	"""
		To configure, make and make install in this function.
		
		Return 0 if all processes are successful.
	"""
	print "[libfuse] start to make and install."
		
	(status, output) = commands.getstatusoutput('make && make install')
	if status ==0:
		print "successfully install"
		return 0	
	else:	
		error_log("== output of configure ==\n" + output)
		print "unsuccessfully install"
		return -1			
		
if __name__ == '__main__':
	if len(sys.argv) > 1:
		print usage
		sys.exit(-1)
	else:
		if configure_set() == 0:
			if make_install() == 0:
				print '0'
			else:
				print '-1'
		else:
			print '-1'
		