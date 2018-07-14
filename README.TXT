GNU ls ported to Microsoft Windows

This is an adaptation of the GNU `ls' directory information
utility for Microsoft Windows.  It shows informaton on
on NTFS files in a format familiar to UNIX users.

To install: Copy ls.exe to your favorite executable folder for your
command line utilities.  Copy ls.exe C:\Windows\System32\ls.exe.  (On 64-bit 
operating systems also Copy ls.exe C:\Windows\SysWOW64\ls.exe.)

Set the LS_OPTIONS environment variable in Control Panel -> System
-> Advanced -> Environment Variables.  The recommended settings are:

   -bhAC --more --color=auto --recent --streams

For documentation view msls.htm in your web browser.
For updates go to https://u-tools.com/msls.asp.
Send feedback and bug reports to msls@algintech.com.

Also included is the native Windows version of the `grep' text search 
utility.  It understands backslash notation, e.g., grep "search" *\*.txt
Use the environment variable GREP_OPTIONS:

	--binary-files=text -d skip --color=auto

`ls' is updated whenever Microsoft releases a new versions of of Windows.
Get the latest version from
     https://u-tools.com/download.asp

Alan Klietz, April 2017
