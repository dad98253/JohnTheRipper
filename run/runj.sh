#! /bin/bash
#./configure --disable-opencl --disable-openmp --enable-cuda --disable-rexgen


#make clean
#make  or make debug


#./john --format=sha512crypt-cuda passwords


#./john --debug-flags=TRACE --debug-level=1 --debug-device=TCPPORT --debug-server=firewall3 --debug-color=1 --format=sha512crypt-cuda  passwords
#./john --debug-level=1 --debug-device=TCPPORT --debug-server=firewall3 --debug-color=1 --format=sha512crypt-cuda  passwords
#./john --debug-flags=TRACE --debug-level=1  --debug-server=firewall3 --debug-color=1 --format=sha512crypt-cuda  passwords
#./john --debug-flags=TRACE,TRACE2,DEBUGSALTDUMP,DMPFMTMAIN,DMPDBMAIN,DYNASALTDEBUG,DEBUGQUIET --debug-level=1 --debug-device=FILEOUTPUT --debug-filename=debug_nogui_calltrace2.txt --debug-color=0 --format=sha512crypt-cuda  passwords
#./john --debug-flags=TRACE,TRACE2,DMPDBMAIN --debug-level=1 --debug-device=FILEOUTPUT --debug-filename=debug_nogui_calltrace2.txt --debug-color=0 --format=sha512crypt  passwords
#./john --debug-flags=TRACE,TRACE2,DEBUGQUIET --debug-level=1 --debug-device=FILEOUTPUT --debug-filename=debug_nogui_calltrace2.txt --debug-color=0 --format=sha512crypt-cuda  passwords
#./john --debug-flags=TRACE,TRACE2,QUIET,TRACECRACKER --debug-level=1 --debug-device=TCPPORT --debug-server=firewall3 --debug-clrscr=3 --debug-color=1 --format=sha512crypt-cuda  passwords
./john --debug-flags=ALLON --debug-level=1 --debug-device=TCPPORT --debug-server=firewall3 --debug-clrscr=0 --debug-color=1 --format=sha512crypt-cuda  passwords


