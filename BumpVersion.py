import sys
import re
import time

#
# Bump the version number in the file ls.manifest
#
# Side effect:
#	Also bump the version in ls.rc and config.h
#

szManifestFile = 'ls.manifest'
szRcFile = "ls.rc"
szConfigFile = "config.h"

gstrVer = None
gstrFullVer = None

#
# Find szPat and substitute szRepl in szBody
#
def _subst(szPat, szRepl, szBody, nInstances=1):

	nSubs = 0
	szResult = ""

	while nInstances > 0:
		nInstances -= 1

		m = re.search(szPat, szBody)
		if not m:
			if nSubs == 0:  # if no substitutions were successful
				raise KeyError("Unable to find " + szPat)
			break

		nSubs += 1

		(start, end) = m.span(1)

		szResult = szResult + szBody[0:start] + szRepl
		szBody = szBody[end:]

	return szResult + szBody

#
# Bump the version in the .manifest file.
#
# Side effect: extracts and caches gstrVer
#
def BumpManifest():
	global gstrVer  # must declare global to set it
	global gstrFullVer

	f = open(szManifestFile, "r")
	text = f.read()
	f.close()

	#
	# version="4.3.174.1"
	#
	m = re.search(R'version\s*=\s*"([0-9])+\.([0-9])+\.([0-9]+)', text)
	if not m:
			raise KeyError("Unable to find version in " + szManifestFile)

	(start, end) = m.span(3)

	iVer = int(text[start:end])
	iVer = iVer + 1
	gstrVer = str(iVer)  # "473"

	text = text[0:start] + gstrVer + text[end:]  # "4.3.473"

	gstrFullVer = m.group(1) + '.' + m.group(2) + '.' + gstrVer

	f = open(szManifestFile, "w")
	f.write(text)
	f.close()


#
# Bump the version in the .rc file
#
def BumpRcFile():

	f = open(szRcFile, "r")
	text = f.read()
	f.close()

	# "1,0,218,1"
	text = _subst(R'FILEVERSION\s+[0-9]+,\s*[0-9]+,\s*([0-9]+)', gstrVer, text)
	text = _subst(R'PRODUCTVERSION\s+[0-9]+,\s*[0-9]+,\s*([0-9]+)', gstrVer, text)
	# "1.0.218.1"
	text = _subst(R'"FileVersion",\s*"[0-9]+\.[0-9]+\.([0-9]+)', gstrVer, text)
	text = _subst(R'"ProductVersion",\s*"[0-9]+\.[0-9]+\.([0-9]+)', gstrVer, text)

	f = open(szRcFile, "w")
	f.write(text)
	f.close()


#
# Bump the #define VERSION in config.h
#
def BumpConfigFile():

	f = open(szConfigFile, "r")
	text = f.read()
	f.close()

	#  #define VERSION "4.3.174 2007/10"
	text = _subst(R'#define\s+VERSION\s+"[0-9]+\.[0-9]+\.([0-9]+\s+[0-9]+/[0-9]+)"',
			gstrVer + ' ' + time.strftime('%Y/%m'),
			text)
	f = open(szConfigFile, "w")
	f.write(text)
	f.close()


def DoBump():
	BumpManifest()
	BumpRcFile()
	BumpConfigFile()

	print('Version bumped to ' + gstrFullVer)


def main():
	DoBump()

if __name__=='__main__':
	sys.path.append('.')  # search cwd for .py files
	main()
