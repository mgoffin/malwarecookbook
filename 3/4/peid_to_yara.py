#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
"""
untitled.py

Created by Matthew Richard on 2010-03-12.
Copyright (c) 2010. All rights reserved.
"""

import sys
import os
import re
from optparse import OptionParser

def main():
	parser = OptionParser()
	parser.add_option("-f", "--file", action="store", dest="filename",
	             type="string", help="scanned FILENAME")
	parser.add_option("-o", "--output-file", action="store", dest="outfile",
			type="string", help="output filename")
	parser.add_option("-v", "--verbose", action="store_true", default=False,
					dest="verbose", help="verbose")
	parser.add_option("-n", "--no-ep", action="store_true", default=False,
					dest="no_ep", help="no entry point restriction")

	(opts, args) = parser.parse_args()

	if opts.filename == None:
		parser.print_help()
		parser.error("You must supply a filename!")
	if not os.path.isfile(opts.filename):
		parser.error("%s does not exist" % opts.filename)
		
	if opts.outfile == None:
		parser.print_help()
		parser.error("You must specify an output filename!")
		
	# yara rule template from which rules will be created
	yara_rule = """
rule %s
{
strings:
	%s
condition:
	%s
}
	
	"""
	rules = {}
	
	# read the PEiD signature file as the first argument
	data = open(opts.filename, 'rb').read()

	# every signature takes the form of
	# [signature_name]
	# signature = hex signature
	# ep_only = (true|false)
	signature = re.compile('\[(.+?)\]\r\nsignature = (.+?)\r\nep_only = (.+?)\r\n', re.M|re.S)
	
	matches = signature.findall(data)
	if opts.verbose:
		print "Found %d signatures in PEiD input file" % len(matches)
	for match in matches:

		# yara rules can only contain alphanumeric + _
		rulename_regex = re.compile('(\W)')
		rulename = rulename_regex.sub('', match[0])

		# and cannot start with a number
		rulename_regex = re.compile('(^[0-9]{1,})')
		rulename = rulename_regex.sub('', rulename)

		# if the rule doesn't exist, create a dict entry
		if rulename not in rules:
			rules[rulename] = []
		
		signature = match[1]

		# add the rule to the list
		rules[rulename].append((signature, match[2]))

	output = ''
	
	for rule in rules.keys():
		detects = ''
		mod_ep = False
		conds = '\t'
		x = 0
		for (detect, ep) in rules[rule]:
			# check for rules that start with wildcards
			# this is not allowed in yara, nor is it particularly useful
			# though it does goof up signatures that need a few wildcards
			# at EP
			while detect[:3] == '?? ':
				detect = detect[3:]
				if opts.no_ep == True:
					if opts.verbose:
						print "\t\tSince you said no_ep, I'll skip the ep."
					mod_ep == True
				if opts.verbose:
					print "\tTrimming %s due to wildcard at start" % rule
			# create each new rule using a unique numeric value
			# to allow for multiple criteria and no collisions
			detects += "\t$a%d = { %s }\r\n" % (x, detect)

			if x > 0: 
				conds += " or "
			
			# if the rule specifies it should be at EP we add
			# the yara specifier 'at entrypoint'
			if ep == 'true' and mod_ep == False:
				conds += "$a%d at entrypoint" % x
			else:
				conds += "$a%d" % x
			x += 1

		# add the rule to the output
		output += yara_rule % (rule, detects, conds)

	# could be written to an output file
	fout = open(opts.outfile, 'wb')
	fout.write(output)
	fout.close()
	if opts.verbose:
		print "Wrote %d rules to %s" % (len(rules), opts.outfile)

if __name__ == '__main__':
	main()

