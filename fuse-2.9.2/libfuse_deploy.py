#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import os
import sys
import commands
import time, datetime


usage =  'python libfuse_deploy.py [target_path]' 

def error_log(string):
	"""
		Create the log file to record errors
	"""
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	
	file = open("./libfuse-deploy-err.log", "a")
	file.write("[%s] %s\n\n" %(st, string) )
	file.close()

def copy_dir(path):
	(status, output) = commands.getstatusoutput('cp -r ./libfuse_build/usr/* %s/usr/' % path)
	if status == 0:
		(status1, output1) = commands.getstatusoutput('rm -rf ./libfuse_build')	
		if status1 == 0:
			print 'successfullu copy'
			return 0
		else:
			print 'unsuccessfullu remove directory'
			return -1
	else:
		error_log("== output of copy_dir ==\n" + output)
		print 'unsuccessfullu copy'
		return -1
	
if __name__ == '__main__':
	if len(sys.argv) < 2:
		print usage
		sys.exit(-1)
	else:
		path = sys.argv[1]
		if copy_dir(path) == 0:
			print '0'
		else:
			print '-1'