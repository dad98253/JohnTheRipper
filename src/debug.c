#ifdef DEBUG

#ifdef WINDOZE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#else
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <malloc.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include "fmt_externs.h"

#define DEFAULT_PORT 5001
#ifdef WINDOZE
#define DEFAULT_PROTO SOCK_DGRAM // UDP
#else
#define DEFAULT_PROTO 2
//#define DEFAULT_PROTO SOCK_DGRAM // UDP
//#define INVALID_SOCKET	-1
#define SOCKET_ERROR	-1
#endif

#define DEBUGMAIN
#include "debug.h"

#undef far
#define far

#ifndef TRUE
#define TRUE                1
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef CONST
#define CONST               const
#endif

typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef const char *	LPCTSTR;
typedef char *		LPSTR;
typedef unsigned char       BYTE;
typedef int                 BOOL;
typedef int                 bool;
typedef void far            *LPVOID;
typedef CONST void far      *LPCVOID;
typedef long		HANDLE;
typedef HANDLE *	JKPHANDLE;
typedef HANDLE 		HWND;
typedef unsigned int 	ULONG_PTR, UINT_PTR;
typedef char *		LPTSTR;
typedef void		VOID, *PVOID;
typedef DWORD far *     LPDWORD;
typedef unsigned int	SHORT;
typedef int                 INT;
typedef char	CHAR;
typedef char	WCHAR;

typedef struct _OVERLAPPED {
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    };
    PVOID  Pointer;
  };
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

#ifndef bool
    #define bool int
    #define false ((bool)0)
    #define true  ((bool)1)
#endif
#define cdecl
#ifndef CDECL
#define CDECL
#endif
#define WINAPI      CDECL
struct sockaddr_in server;
struct hostent *hp;
#ifdef WINDOZE
WSADATA wsaData;
SOCKET  conn_socket;
#else
int  conn_socket;
extern int h_errno;
#endif
unsigned int addr;
char *server_name;
unsigned short port = DEFAULT_PORT;
int socket_type = DEFAULT_PROTO;
//int socket_type = SOCK_DGRAM;
//int socket_type = DEFAULT_PROTO;

//FILE *hf;
#define LENTEMPSTR	10000
char *str;
char *tmpstr;

EXTERN char * lpDebugOutputFileName;
// lpDebugOutputFileName is the optional name for the debug output file.
// ==NULL (i.e., a NULL pointer) debug output goes to the default debug output device
// COMx => debug output is to go to a serial port x
// CON  => debug output is to go to a console screen
// PORT => debug output is to go to UDP port x as a service (requires appropriate firewall permission)
// NULL => debug output goes to the bit bucket
// DEBUG => debug output goes to the debug window
// <anything else> => is assumed to be a file name
EXTERN int iDebugOutputDevice;
// iDebugOutputDevice is set by passwin to indicate the type of device tosend debug output to
// 0 => a normal output file (default)
// 1 => a serial port
// 2 => a console screen
// 3 => a TCPIP port
// 4 => the bit bucket
// 5 => the debug window
EXTERN char * lpDebugServerName;
// lpDebugServerName is the optional name for the debug output server. This argument has no meaning
// unless the "PORT" option is specified for iDebugOutputDevice.
// If lpDebugServerName is NULL (not specified) the default server name is localhost.
// If the value of lpDebugServerName starts with a number, it is assumed to be an IP4 address in dot
// notation.
// <anything else> => lpDebugServerName is assumed to be a DNS name.
EXTERN unsigned short iDebugServerPort INITIZERO;
// iDebugServerPort is the optional port number for the debug output server. This argument has no meaning
// unless the "PORT" option is specified for iDebugOutputDevice. If the port number is set to '0', then the
// default port number = 5001 is used.
EXTERN int ClearDebugScreenOnExit;
// option to clear the text from the debug screen. Note that this only works if the
// debug terminal is an ANSII terminal and the program terminates properly (won't clear on a crash)
// ClearDebugScreenOnExit == 0 => don't clear the screen (default)
// ClearDebugScreenOnExit == 1 or 3 => send ascii escape sequence ["[2J"] to clear the screen on exit
// ClearDebugScreenOnExit == 2 or 3 => send ascii escape sequence ["[2J"] to clear the screen at start
// ClearDebugScreenOnExit == anything else => don't clear the screen
#define BADUPRSTRCCALL		1
#define SUCCESS			0

typedef struct _DCB {
  DWORD DCBlength;
  DWORD BaudRate;
  DWORD fBinary  :1;
  DWORD fParity  :1;
  DWORD fOutxCtsFlow  :1;
  DWORD fOutxDsrFlow  :1;
  DWORD fDtrControl  :2;
  DWORD fDsrSensitivity  :1;
  DWORD fTXContinueOnXoff  :1;
  DWORD fOutX  :1;
  DWORD fInX  :1;
  DWORD fErrorChar  :1;
  DWORD fNull  :1;
  DWORD fRtsControl  :2;
  DWORD fAbortOnError  :1;
  DWORD fDummy2  :17;
  WORD  wReserved;
  WORD  XonLim;
  WORD  XoffLim;
  BYTE  ByteSize;
  BYTE  Parity;
  BYTE  StopBits;
  char  XonChar;
  char  XoffChar;
  char  ErrorChar;
  char  EofChar;
  char  EvtChar;
  WORD  wReserved1;
} DCB, *LPDCB;
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
typedef struct _COORD {
  SHORT X;
  SHORT Y;
} COORD, *PCOORD;
typedef struct _SMALL_RECT {
  SHORT Left;
  SHORT Top;
  SHORT Right;
  SHORT Bottom;
} SMALL_RECT;
typedef struct _CONSOLE_SCREEN_BUFFER_INFO {
    COORD dwSize;
    COORD dwCursorPosition;
    WORD  wAttributes;
    SMALL_RECT srWindow;
    COORD dwMaximumWindowSize;
} CONSOLE_SCREEN_BUFFER_INFO, *PCONSOLE_SCREEN_BUFFER_INFO;
typedef struct _CHAR_INFO {
  union {
    WCHAR UnicodeChar;
    CHAR  AsciiChar;
  } Char;
  WORD  Attributes;
} CHAR_INFO, *PCHAR_INFO;

#define STD_ERROR_HANDLE		(DWORD)-12
#define INVALID_HANDLE_VALUE	-1
#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define OPEN_EXISTING			3
#define NOPARITY            0
#define ODDPARITY           1
#define EVENPARITY          2
#define MARKPARITY          3
#define SPACEPARITY         4
#define ONESTOPBIT          0
#define ONE5STOPBITS        1
#define TWOSTOPBITS         2
#define CREATE_NEW		1
#define CREATE_ALWAYS       	2
#define OPEN_EXISTING		3
#define MB_YESNO			4
#define MB_ICONQUESTION		0x20
#define MB_ICONEXCLAMATION	0x30
#define MB_ICONERROR		0x10
#define MB_OK				0
#define IDOK				1
#define IDCANCEL			2
#define IDYES				6
#define IDNO				7
#define FOREGROUND_RED       0x0004 // text color contains red.
#define FOREGROUND_INTENSITY 0x0008 // text color is intensified.
#define CONSOLE_TEXTMODE_BUFFER  1
#define STD_INPUT_HANDLE		(DWORD)-10
#define STD_OUTPUT_HANDLE		(DWORD)-11
#define STD_ERROR_HANDLE		(DWORD)-12
#define ENABLE_LINE_INPUT      0x0002
#define ENABLE_ECHO_INPUT      0x0004
#define _In_
#define _In_opt_
#define _Out_
#define _In_Out_
#define _Inout_
#define _Out_opt_
#define _Reserved_
#define lstrlenA  strlen

// static variables
bool fDebug = TRUE;
bool bMyWay = TRUE;
HANDLE hCom;
HANDLE hStdout, hStdin, hStderr; 
char * lpHeapFile;
int iStartOfHeapFile;
FILE *hpfile;
HANDLE hStdout, hStdin, hStderr; 
HANDLE hConsoleBuffer;
CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
pid_t mypid;
pid_t myppid;

// If bTextMode is set to true (non-zero), the program will revert to a "text  only" mode and no windows
// will be created.
EXTERN bool bTextMode INITBOOLFALSE;
// lpszMsgBoxBanner is a long pointer to a string used as the banner to MessageBox messages displayed by MsgBox.
// If it is set to NULL, MsgBox will use a blank banner.
EXTERN bool bIsStdinTty INITBOOLFALSE;
EXTERN bool bOutputDP INITBOOLFALSE;
EXTERN char * lpszMsgBoxBanner INITNULL;	
EXTERN HWND hWnd ;
	const char * OuputDeviceType[] = {
		"FILEOUTPUT",
		"SERIALPORT",
		"CONSOLE",
		"TCPPORT",
		"BITBUCKET",
		"DEBUGWIN",
		"RAM"
	};

// functions
int OpenTCPport(void);
int SetUpDebugConsole(void);
int IPSend(char * data, int MaxDataSize);
int ClosePort(void);
int OpenDebugDevice();
int CloseDebugDevice();
void DumpRamFile(char **lpHeapFile);
bool SaveStringInHeap(char **lpHeapFile,char *str);
bool StripCSI(char *ci, char *co);
int MsgBox(const char * message, ...);
int ErrorMessageTX(LPSTR msg, unsigned int mode);
int MessageBoxTX(const char * msg, const char * lpszBanner, unsigned int mode);
size_t _msize(void *memblock);
int tutPrintString (const char * szText);
void NewLine(void); 
void ScrollScreenBuffer(HANDLE, INT); 
int ReAllocateCharVector(unsigned char **p, int length);
BOOL WINAPI WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
DWORD WINAPI GetLastError(void);
void WINAPI OutputDebugString(LPCTSTR lpOutputString);
DWORD WINAPI GetProfileString(LPCTSTR lpAppName,LPCTSTR lpKeyName,LPCTSTR lpDefault,LPTSTR lpReturnedString,DWORD nSize);
HANDLE WINAPI CreateFile(LPCTSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,JKPHANDLE hTemplateFile);
BOOL WINAPI SetupComm(HANDLE hFile,DWORD dwInQueue,DWORD dwOutQueue);
BOOL WINAPI GetCommState(HANDLE hFile,LPDCB lpDCB);
BOOL WINAPI SetCommState(HANDLE hFile,LPDCB lpDCB);
BOOL WINAPI FlushFileBuffers(HANDLE hFile);
BOOL WINAPI FreeConsole(void);
HANDLE WINAPI CreateConsoleScreenBuffer(_In_ DWORD dwDesiredAccess,_In_ DWORD dwShareMode,_In_opt_ const SECURITY_ATTRIBUTES *lpSecurityAttributes,_In_ DWORD dwFlags,_Reserved_ LPVOID lpScreenBufferData);
BOOL WINAPI ScrollConsoleScreenBuffer(_In_ HANDLE hConsoleOutput,_In_ const SMALL_RECT *lpScrollRectangle,_In_opt_ const SMALL_RECT *lpClipRectangle,_In_ COORD dwDestinationOrigin,_In_ const CHAR_INFO *lpFill);
BOOL WINAPI AllocConsole(void);
BOOL WINAPI GetConsoleScreenBufferInfo(_In_ HANDLE hConsoleOutput,_Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);
BOOL WINAPI SetConsoleTextAttribute(_In_ HANDLE hConsoleOutput,_In_ WORD wAttributes);
BOOL WINAPI SetConsoleScreenBufferSize(_In_ HANDLE hConsoleOutput,_In_ COORD dwSize);
BOOL WINAPI GetConsoleMode(_In_ HANDLE hConsoleHandle,_Out_ LPDWORD lpMode);
BOOL WINAPI SetConsoleMode(_In_ HANDLE hConsoleHandle,_In_ DWORD dwMode);
BOOL WINAPI SetConsoleCursorPosition(_In_ HANDLE hConsoleOutput,_In_ COORD dwCursorPosition);

//#define MIN(x, y) (((x) > (y)) ? (y) : (x))    //  defined in getopt.h

int debug_read_proc_file(int idumpem) 
{
#define MAXPFNAMELEN	100
	char pfname[MAXPFNAMELEN];
	char maploc[MAXPFNAMELEN];
	char mode[MAXPFNAMELEN];
	char *line = NULL;
	FILE *procfile;
	ssize_t linelen;
	size_t maxlen = 0;
	int numread,pfnlen;
	unsigned int startoffset,devmaj,devmin,inode;
	unsigned long long int startadd,endadd;
	
	mypid = getpid();
	myppid = getppid();
	pfnlen = snprintf(pfname,MAXPFNAMELEN,"/proc/%u/maps",(unsigned int)mypid);
	if (pfnlen > (MAXPFNAMELEN - 2) ) {
		fprintf(stderr,"unable to construct proc file name : %s\n",pfname);
		exit(EXIT_FAILURE);
	}
	if ((procfile = fopen(pfname, "r")) == NULL) {
		fprintf(stderr,"unable to open %s file.\n",pfname);
		exit(EXIT_FAILURE);
	}
	while ( (linelen = getline(&line, &maxlen, procfile)) > 0 ) {
		numread=strlen(line);
		if(numread>0) line[numread-1]='\000';
		if ( idumpem ) dfprintf(__LINE__,__FILE__,NOHEADspecial," %s\n", line);
		numread = sscanf ( line, "%llx-%llx %s %x %x:%x %u %s", &startadd,&endadd,mode,&startoffset,&devmaj,&devmin,&inode,maploc);
		if ( numread != 7 && numread != 8 ) {
			fprintf(stderr,"unable to parse line in /proc/../maps file : %s \n",line);
			fclose(procfile);
			exit(EXIT_FAILURE);
		}
		free(line);
		line = NULL;
		if (strcmp(maploc,"[heap]") == 0 ) {
			debugheapstart = startadd;
			debugheapend = endadd;			
		}
		if (strcmp(maploc,"[stack]") == 0 ) {
			debugstackstart = startadd;
			debugstackend = endadd;			
		}
	}
	fclose(procfile);

	return 0;
}

int debug_init () 
{
	int truesize;
	int retvalue = 0;
	debug_read_proc_file(0);
//fprintf(stderr,"debugheapstart = %llx, debugheapend = %llx, debugstackstart = %llx, debugstackend = %llx\n",debugheapstart, debugheapend, debugstackstart, debugstackend);
//exit(EXIT_FAILURE);
	truesize = sizeof(debug_flag)/sizeof(debug_flag[0]);
	if ( truesize != NUMDEBUGFLAGS ) {
		fprintf(stderr,"bad dimention on debug_flag array, true size = %i, NUMDEBUGFLAGS = %i\n",truesize,NUMDEBUGFLAGS);
		retvalue++;
	}
	truesize = sizeof(bdebug_flag_set)/sizeof(bdebug_flag_set[0]);
	if ( truesize != NUMDEBUGFLAGS ) {
		fprintf(stderr,"bad dimention on bdebug_flag_set array, true size = %i, NUMDEBUGFLAGS = %i\n",truesize,NUMDEBUGFLAGS);
		retvalue+=2;
	}
	if (retvalue) return(retvalue);
//char str[LENTEMPSTR];
//char tmpstr[LENTEMPSTR];
	str=malloc(LENTEMPSTR);
	tmpstr=malloc(LENTEMPSTR);
	bOutputDP = bIsStdinTty = isatty(STDIN_FILENO);
	return(0);
}

void load_debug () 
{
	struct list_entry *current;
	int i;
	int j=0;
	int k=0;
	int iflagset;
	char *isset[] = { "not set", "set" };

	if ( options.debug_level > 0 ) fprintf(stderr,"   debug verbosity = %i\n",options.debug_level);
	if ( options.debug_level > 0 ) debugInitialVirbosity = debugVirbosity = options.debug_level;

	bdebug_flag_set[0] = bdebug_flag_set[NUMDEBUGFLAGS-1] = 0;

	if ( (current = options.debug_flags->head) )
	{
		do {
			k++;
			for(i=0;i<NUMDEBUGFLAGS;i++) {
				if( strcmp(debug_flag[i], current->data) == 0 ) {
					bdebug_flag_set[i] = 1;
					j++;
				}
			}
			if ( j != k ) fprintf(stderr, " %s is not a valid debug flag\n", current->data);
		} while ((current = current->next));
	}
	if ( j != k ) {
		fprintf(stderr," see --list=debug-flags\n");
		exit(EXIT_FAILURE);
	}
	if ( bdebug_flag_set[ALLON] ) {
		for(i=0;i<NUMDEBUGFLAGS;i++){
			if ( i != QUIET && i != NONE ) bdebug_flag_set[i]=1;
		}
	} 
	if ( (current = options.debug_flags->head) ) {
		fprintf(stderr,"   debug flags set : ");
		do {
			fprintf(stderr, "%s", current->data);
			if ( current->next ) fprintf(stderr, ",");
		} while ( ( current = current->next ) );
		fprintf(stderr,"\n");
	}

	iDebugOutputDevice = -1;

	if ( options.debug_server_name != NULL ) lpDebugServerName = options.debug_server_name;
	if ( options.degug_port_number != 0 ) port = options.degug_port_number;
	if ( options.debug_filename != NULL ) lpDebugOutputFileName = options.debug_filename;
	if ( options.debug_device != NULL ) {
		for(i = 0;i < DIMDEBUGDEVICES;i++) {
			if ( strcmp (OuputDeviceType[i] , options.debug_device) == 0 ) iDebugOutputDevice = i;
		}
		if ( iDebugOutputDevice == -1 ) {
			iDebugOutputDevice = BITBUCKET;
			fprintf(stderr," %s is not a valid debug output device, see --list=debug-device\n", options.debug_device);
			exit(EXIT_FAILURE);
		}
	}
	if ( options.debug_color_flag != 0 ) { ColorDebug = 1; }
		else ColorDebug = 0;
	if ( options.debug_clear_screen > 0 && options.debug_clear_screen < 4) { ClearDebugScreenOnExit = options.debug_clear_screen; }
		else ClearDebugScreenOnExit = 0;
	if ((current = options.debug_mask_messages->head)) {
		printf("messages to mask:\n");
		do {
			printf("   %s\n",current->data);
		} while ((current = current->next));
	}
	if ((current = options.debug_display_messages->head)) {
		printf("messages to display:\n");
		do {
			printf("   %s\n",current->data);
		} while ((current = current->next));
	}

//	iDebugOutputDevice = iDebugOutputDeviceSave;
//	if (debugflag > 0) {
		if ( OpenDebugDevice() == 0 ) {
			fprintf(stderr,"OpenDebugDevice failed\n");
		} else {
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32mDebug output device set to type %i\33[0m (%s)\n", iDebugOutputDevice,OuputDeviceType[iDebugOutputDevice]);
			iflagset = 0;
#ifdef JUMBO_JTR
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m JUMBO_JTR is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef BENCH_BUILD
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m BENCH_BUILD is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef _MSC_VER
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m _MSC_VER is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef ARCH_ALLOWS_UNALIGNED
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m ARCH_ALLOWS_UNALIGNED is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef HAVE_OPENCL
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m HAVE_OPENCL is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef HAVE_CUDA
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m HAVE_CUDA is %s\33[0m\n", isset[iflagset]);
			iflagset = 0;
#ifdef DYNA_SALT_DEBUG
			iflagset = 1;
#endif
			dfprintf(__LINE__,__FILE__,DEBUGINIT,"\33[1;32m DYNA_SALT_DEBUG is %s\33[0m\n", isset[iflagset]);
		}
		if ( bdebug_flag_set[QUIET] ) debugVirbosity = 0;

//	}
	return;
}

unsigned char debugSetDBLevel( int DesiredLevel )
{
	unsigned char OldLevel;

	OldLevel = debugVirbosity;
	if ( DesiredLevel < 0 ) {
		debugVirbosity = debugInitialVirbosity;
	} else {
		debugVirbosity = (unsigned char)DesiredLevel;
	}

	return(OldLevel);
}

void debug_close () {
	free(str);
	free(tmpstr);
	CloseDebugDevice();
	return;
}

int Dbgdmpprintf( const char * fmt,...)
{
va_list args;

int nTmp;

    va_start(args, fmt);
    nTmp = Dbgprintf(0,"", NOHEADspecial, fmt, args);

    va_end(args);
    return(nTmp);
}

int Dbg2dmpprintf( unsigned int debugflag, const char * fmt,...)
{
va_list args;

int nTmp;

    va_start(args, fmt);
    nTmp = Dbgprintf(0,"", NOHEADspecial+debugflag, fmt, args);

    va_end(args);
    return(nTmp);
}

int Dbgprintf(int linenum, const char * modulename, unsigned int debugflag, const char * fmt,...)
{
va_list args;

int nTmp,jkTmp;
unsigned long numout;
HANDLE hStderr;

    va_start(args, fmt);
/*
	if ( !bMyWay ) return -1;
	if ( debugflag > NUMDEBUGFLAGS && ( debugflag < NOHEADspecial || debugflag > ( NOHEADspecial + NUMDEBUGFLAGS ) ) ) {
		MsgBox("Dbgprintf at %i in %s failed, \"%u\" is not a valid debug flag number\n debug flag numbers must be less than %u",linenum,modulename,debugflag,NUMDEBUGFLAGS);
		bMyWay=FALSE;
		return(-1);
	}
	if ( debugflag == 0 ) {
		return(0);
	}
	if ( debugflag < HEADUNCOND ) if ( bdebug_flag_set[debugflag] == 0 ) {
		return(0);
	}
	if ( debugflag > NOHEADspecial ) if ( bdebug_flag_set[debugflag-NOHEADspecial] == 0 ) {
		return(0);
	}
*/
	if ( !debugCheckflags( debugflag ) ) return(0);
	str[0]='\000';
	tmpstr[0]='\000';
	nTmp=vsprintf(tmpstr,fmt,args);
	assert(nTmp<LENTEMPSTR);
	if ( debugflag >= NOHEADspecial ) {
		nTmp=sprintf(str,"%s",tmpstr);
	} else {
		nTmp=sprintf(str,DBGBOLDGREEN(line)" "DBGBOLDRED(%i)" "DBGBOLDGREEN(in)" "DBGBOLDRED(%s)": %s",linenum,modulename,tmpstr);
	}
	assert(nTmp<LENTEMPSTR);
	switch (iDebugOutputDevice)
      {
      case FILEOUTPUT:
		if ( !ColorDebug ) {
			strcpy(tmpstr,str);
			StripCSI(tmpstr,str);
			nTmp=strlen(str);
		}
//		str[nTmp]='\n';
//		nTmp++;
		str[nTmp]='\000';
//		  if ((int)fwrite(str, sizeof(str[0]), nTmp, hpfile) != nTmp ) {
		  if ((jkTmp=(int)fprintf(hpfile,"%s",str)) != nTmp ) {
			 fflush(hpfile);
			 MsgBox("Write to debug file failed, GetLastError=%i,\n disabling future writes",GetLastError());
			 bMyWay=FALSE;
			return (-1);
		  }
		fflush(hpfile);
        break;

      case SERIALPORT:
		if ( !ColorDebug ) {
			strcpy(tmpstr,str);
			StripCSI(tmpstr,str);
			nTmp=strlen(str);
		}
		str[nTmp]='\r';
		nTmp++;
		if ( !WriteFile( hCom, str, nTmp, &numout, NULL) )
		{
			 MsgBox("WriteFile to COM port failed, GetLastError=%i,\n disabling future writes",GetLastError());
			 bMyWay=FALSE;
			return (-1);
		}
		break;

	  case CONSOLE:
//		str[nTmp]='\n';
//		nTmp++;
		if ( !ColorDebug ) {
			strcpy(tmpstr,str);
			StripCSI(tmpstr,str);
		}
		hStderr = GetStdHandle(STD_ERROR_HANDLE);
		if (hStderr == INVALID_HANDLE_VALUE)
		{
			 MsgBox("GetStdHandle for Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
			 bMyWay=FALSE;
			return (-1);
		}
		if ( !WriteFile( hStderr, str, nTmp, &numout, NULL) )
		{
			MsgBox("WriteFile to Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
			bMyWay=FALSE;
			return (-1);
		}
		break;

	  case TCPPORT:

		if ( !ColorDebug ) {
			strcpy(tmpstr,str);
			StripCSI(tmpstr,str);
		}
		IPSend(str, strlen(str)+1);	

		break;

	  case BITBUCKET:
		break;
	  
	  case DEBUGWIN:
		strcpy(tmpstr,str);
		StripCSI(tmpstr,str);
		OutputDebugString(str);
		break;

	  case RAM:
		SaveStringInHeap(&lpHeapFile,str);
		dfprintf(__LINE__,__FILE__,DEBUGDBGPRINTF,"%s",str);

		break;
	}

    va_end(args);
    return(nTmp);
}

int OpenDebugDevice()
{
    DCB dcb;
    bool fSuccess;
    unsigned long numout;
#define LENTEMPLINE	250
	char *line = NULL;

	SaveStringInHeap(&lpHeapFile,(char*)"$e$n$d$o$f$f$i$l$e$");

	switch (iDebugOutputDevice)
      {

      case FILEOUTPUT:
			if ( lpDebugOutputFileName == NULL ) {
				if ((hpfile = fopen("debug.txt", "w")) == NULL) {
					MsgBox("unable to open debug.txt file.");
					return 0;
				}
			} else {
				if ((hpfile = fopen(lpDebugOutputFileName, "w")) == NULL) {
					MsgBox("unable to open debug.txt file.");
					return 0;
				}
			}
			break;

      case SERIALPORT:
			line = (char *)realloc( line , LENTEMPLINE);

			if ( GetProfileString ("john","DefaultComPort","",line,LENTEMPLINE+2) ==
                                                             0 )
			{
				if (lpDebugOutputFileName == NULL ) {
					MsgBox("Open COM port failed, GetLastError=%i\n\0",GetLastError());
					bMyWay=FALSE;
					return 0;
				}
				strncpy(line,lpDebugOutputFileName,LENTEMPLINE);
			}
			hCom = CreateFile(line,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,
                       0,NULL);
			free(line);

			if (hCom==INVALID_HANDLE_VALUE)
			{
			   MsgBox("CreateFile failed, GetLastError=%i\n\0",GetLastError());
			   bMyWay=FALSE;
			  return 0;
			}

//    fSuccess=PurgeComm(hCom,
//                       PURGE_TXABORT|
//                       PURGE_RXABORT|
//                       PURGE_TXCLEAR|
//                       PURGE_RXCLEAR);
//    if (!fSuccess)
//    {
//        MsgBox("PurgeComm failed, GetLastError=%i\n\0",GetLastError());
//        bMyWay=FALSE;
//        return;
//    }

			fSuccess=SetupComm(hCom,1600,1600);
			if (!fSuccess)
			{
				MsgBox("SetupComm failed, GetLastError=%i\n\0",GetLastError());
				bMyWay=FALSE;
				return 0;
			}

			fSuccess=GetCommState(hCom, &dcb);
			if (!fSuccess)
			{
				MsgBox("GetCommState failed, GetLastError=%i\n\0",GetLastError());
				bMyWay=FALSE;
				return 0;
			}

			dcb.BaudRate=4800;
			dcb.ByteSize=8;
			dcb.Parity=NOPARITY;
			dcb.StopBits=ONESTOPBIT;

			fSuccess=SetCommState(hCom,&dcb);
			if (!fSuccess)
			{
				MsgBox("SetCommState failed, GetLastError=%i\n\0",GetLastError());
				bMyWay=FALSE;
				return 0;
			}
			if ( ColorDebug ) {
				if ( ClearDebugScreenOnExit > 1 ) {
					if ( !WriteFile( hCom, DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 1, &numout, NULL) )
					{
						 MsgBox("WriteFile to COM port failed, GetLastError=%i,\n disabling future writes",GetLastError());
						 bMyWay=FALSE;
						return (-1);
					}
				}
				if ( !WriteFile( hCom, DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 1, &numout, NULL) )
				{
					 MsgBox("WriteFile to COM port failed, GetLastError=%i,\n disabling future writes",GetLastError());
					 bMyWay=FALSE;
					return (-1);
				}
			}

			break;

	  case CONSOLE:

			SetUpDebugConsole();
			if ( ColorDebug ) {
				hStderr = GetStdHandle(STD_ERROR_HANDLE);
				if (hStderr == INVALID_HANDLE_VALUE)
				{
					MsgBox("GetStdHandle for Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
					bMyWay=FALSE;
					return (-1);
				}
				if ( ClearDebugScreenOnExit > 1 ) {
					if ( !WriteFile( hStderr, DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 1, &numout, NULL) )
					{
						MsgBox("WriteFile to Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
						bMyWay=FALSE;
						return (-1);
					}
				}
				if ( !WriteFile( hStderr, DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 1, &numout, NULL) )
				{
					MsgBox("WriteFile to Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
					bMyWay=FALSE;
					return (-1);
				}
			}

			break;

	  case TCPPORT:

			if (OpenTCPport()==0) return 0;
			if ( ClearDebugScreenOnExit > 1 ) if ( ColorDebug ) IPSend(DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 2);
			if ( ColorDebug ) IPSend(DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 2);		

			break;

	  case BITBUCKET:
	  case DEBUGWIN:
	  case RAM:
			break;

	}

	DumpRamFile(&lpHeapFile);

    return 1;
}

int CloseDebugDevice()
{
    unsigned long numout;

	switch (iDebugOutputDevice)
      {
      case FILEOUTPUT:
		fclose(hpfile);
        break;

      case SERIALPORT:
		if ( ColorDebug ) {
			if ( ClearDebugScreenOnExit%2 && !bMyWay ) {
				if ( !WriteFile( hCom, DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 1, &numout, NULL) )
				{
					MsgBox("WriteFile to COM port failed, GetLastError=%i,\n disabling future writes",GetLastError());
					bMyWay=FALSE;
					return (-1);
				}
			}
			if ( !WriteFile( hCom, DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 1, &numout, NULL) )
			{
				MsgBox("WriteFile to COM port failed, GetLastError=%i,\n disabling future writes",GetLastError());
				bMyWay=FALSE;
				return (-1);
			}
		}

		FlushFileBuffers(hCom);
		break;

	  case CONSOLE:
		if ( ColorDebug ) {
			hStderr = GetStdHandle(STD_ERROR_HANDLE);
			if (hStderr == INVALID_HANDLE_VALUE)
			{
				MsgBox("GetStdHandle for Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
				bMyWay=FALSE;
				return (-1);
			}
			if ( ClearDebugScreenOnExit%2 && !bMyWay ) {
				if ( !WriteFile( hStderr, DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 1, &numout, NULL) )
				{
					MsgBox("WriteFile to Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
					bMyWay=FALSE;
					return (-1);
				}
			}
			if ( !WriteFile( hStderr, DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 1, &numout, NULL) )
			{
				MsgBox("WriteFile to Console failed, GetLastError=%i,\n disabling future writes",GetLastError());
				bMyWay=FALSE;
				return (-1);
			}
		}
		FreeConsole();
		break;

	  case TCPPORT:

		if ( ClearDebugScreenOnExit%2 && !bMyWay ) if ( ColorDebug ) IPSend(DBGHOMECURSOR DBGCLRSCR, DBGHOMECURSORLEN + DBGCLRSCRLEN + 2);
		if ( ColorDebug ) IPSend(DBGRESETALLATTRIBUTES, DBGRESETALLATTRIBUTESLEN + 2);	
		ClosePort();

		break;

	  case BITBUCKET:
  	  case DEBUGWIN:
	  case RAM:
		break;
	}
	return 1;
}


void DumpRamFile(char **lpHeapFile)
{
	int istart;
	int iend;

	if (*lpHeapFile == NULL) return;

	istart = 1;
	iend = ReAllocateCharVector((unsigned char **)lpHeapFile, 0);

	while ( istart < iend )
	{
		if (strcmp( ((*lpHeapFile)+istart) , "$e$n$d$o$f$f$i$l$e$" ) == 0 ) goto done;
		dfprintf(__LINE__,__FILE__,DEBUGDUMPRAMFILE, ((*lpHeapFile)+istart) );
		istart+= ( strlen( (*lpHeapFile)+istart ) + 1 );
	}

done:
	free(*lpHeapFile);
	*lpHeapFile = NULL;

	return;
}


bool SaveStringInHeap(char **lpHeapFile,char *str)
{
	int istart;
	int iend;
	dfprintf(__LINE__,__FILE__,DEBUGSAVEINSTRING,"save \"%s\" *lpHeapFile=(0x%llx)\n",str,*lpHeapFile);
	istart = ReAllocateCharVector((unsigned char **)lpHeapFile, 0);
	if ( istart == 1 ) {
		**lpHeapFile = '\n';
		iStartOfHeapFile++;
	}
	if ( istart < (iStartOfHeapFile + (int)strlen(str) + 2)) {
		iend   = ReAllocateCharVector((unsigned char **)lpHeapFile, strlen(str)+1 );
		if (iend == 0) {
			fprintf(stderr,"realloc failed in SaveStringInHeap\n");
			return (true);
		}
	}
	dfprintf(__LINE__,__FILE__,DEBUGSAVEINSTRING,"save string at (0x%llx)+%i of length %i\n",*lpHeapFile,istart,(int)strlen(str));
	strcpy(*lpHeapFile+iStartOfHeapFile,str);
	iend = iStartOfHeapFile + strlen(str);
	*(*lpHeapFile+iend) = '\000';
	iStartOfHeapFile+=strlen(str)+1;

	return (false);
}

int OpenTCPport(void) {
	char *default_server_name = (char*)"localhost";
	if ( lpDebugServerName == NULL ) {
		server_name = default_server_name;
	} else {
		server_name = lpDebugServerName;
	}
//fprintf(stderr,"opening server %s for port %i\n",server_name,iDebugServerPort);
#ifdef WINDOZE
	if (WSAStartup(0x202,&wsaData) == SOCKET_ERROR) {
		fprintf(stderr,"WSAStartup failed with error %d\n",WSAGetLastError());
		WSACleanup();
		return 0;
	}
#endif
	//
	// Attempt to detect if we should call gethostbyname() or
	// gethostbyaddr()
	if (isalpha(server_name[0])) {   /* server address is a name */
		hp = gethostbyname(server_name);
	}
	else  { /* Convert nnn.nnn address to a usable one */
		addr = inet_addr(server_name);
		hp = gethostbyaddr((char *)&addr,4,AF_INET);
	}
	if (hp == NULL ) {
#ifdef WINDOZE
#ifdef DEBUGOPENTCPPORT
		fprintf(stderr,"Client: Cannot resolve address [%s]: Error %d\n",
			server_name,WSAGetLastError());
#endif
		WSACleanup();
		return 0;
#else
#ifdef DEBUGOPENTCPPORT
		int errsv = errno;
		int herrsv = h_errno;
		fprintf(stderr,"Client: Cannot resolve address [%s]: Error %d, h_err = %i\n",
			server_name,errsv,herrsv);
		fprintf(stderr,"%s\n", hstrerror(h_errno));
		if (h_errno == HOST_NOT_FOUND) fprintf(stderr,"Note: on linux, ip addresses must have valid RDNS entries\n");
#endif
#endif
//		return 0;
	}

	//
	// Copy the resolved information into the sockaddr_in structure
	//  iDebugServerPort
	memset(&server,0,sizeof(server));
	if ( hp == NULL ){
		server.sin_addr.s_addr = inet_addr(server_name);
		server.sin_family = AF_INET;
	} else {
		memcpy(&(server.sin_addr),hp->h_addr,hp->h_length);
		server.sin_family = hp->h_addrtype;
	}
	if ( iDebugServerPort != 0 ) port = iDebugServerPort;
	server.sin_port = htons(port);

	conn_socket = socket(AF_INET,socket_type,0); /* Open a socket */
	if (conn_socket <0 ) {
#ifdef WINDOZE
		fprintf(stderr,"Client: Error Opening socket: Error %d\n",
			WSAGetLastError());
		WSACleanup();
#else
		int errsv = errno;
		fprintf(stderr,"Client: Error Opening socket: Error %d\n",
				errsv);
#endif
		return 0;
	}

	//
	// Notice that nothing in this code is specific to whether we 
	// are using UDP or TCP.
	// We achieve this by using a simple trick.
	//    When connect() is called on a datagram socket, it does not 
	//    actually establish the connection as a stream (TCP) socket
	//    would. Instead, TCP/IP establishes the remote half of the
	//    ( LocalIPAddress, LocalPort, RemoteIP, RemotePort) mapping.
	//    This enables us to use send() and recv() on datagram sockets,
	//    instead of recvfrom() and sendto()


	if ( hp != NULL ) {
		dfprintf(__LINE__,__FILE__,DEBUGOPENTCPPORT,"Client connecting to: %s\n",hp->h_name); // warning: can cause a loop !
	} else {
		dfprintf(__LINE__,__FILE__,DEBUGOPENTCPPORT,"Client connecting to: %s\n",server_name); // warning: can cause a loop !
	}

	if (connect(conn_socket,(struct sockaddr*)&server,sizeof(server))
		== SOCKET_ERROR) {
#ifdef WINDOZE
		fprintf(stderr,"connect() failed: %d\n",WSAGetLastError());
		WSACleanup();
#else
		int errsv = errno;
		fprintf(stderr,"connect() failed: %d\n",errsv);
#endif
		return 0;
	}

	return 1;
}

int IPSend(char * Buffer, int MaxDataSize) {
	int retval = 0;
#define IPSENDBADLIMIT	100
	static int ibadcalls = 0;

		retval = send(conn_socket,Buffer,strlen(Buffer)+1,0);
		if (retval == SOCKET_ERROR) {
#ifdef WINDOZE
			fprintf(stderr,"send() failed: error %d\n",WSAGetLastError());
			WSACleanup();
#else
		int errsv = errno;
		if ( bMyWay ) {
			fprintf(stderr,"send() failed: error %d, msg = %s\n",errsv,Buffer);
			ibadcalls++;
			if ( ibadcalls > IPSENDBADLIMIT ) bMyWay = FALSE;
		}
		else fprintf(stderr,"send() failed: error %d\n",errsv);
#endif
			return -1;
		}

//		fprintf(stderr,"Sent Data [%s]\n",Buffer);
	return 0;
}

int ClosePort(void) {
#ifdef WINDOZE
	closesocket(conn_socket);
	WSACleanup();
#else
	close(conn_socket);
#endif
	return 1;
}

/*
 * I did some work like this, through much reading of MSDN and the sockets documentation I got a list of differences between Winsocks and POSIX sockets, many are minor, sign differences or type differences.


uses closesocket() to close a socket, instead of close().
uses an int for the third parameter in bind().
uses an int* for the third parameter in accept().
defines a SOCKET as unsigned int.
socket() returns INVALID_SOCKET(unsigned int) on error, *nix returns -1.
connect() returns SOCKET_ERROR(int) on error, *nix returns -1.
bind() returns SOCKET_ERROR(int) on error, *nix returns -1.
listen() returns SOCKET_ERROR(int) on error, *nix returns -1.
accept() returns INVALID_SOCKET(unsigned int) on error, *nix returns -1.
select() returns SOCKET_ERROR(int) on error, *nix returns -1.
send() returns SOCKET_ERROR(int) on error, *nix returns -1.
send() uses an int for the third parameter (length).
recv() returns SOCKET_ERROR(int) on error, *nix returns -1.
setsockopt() returns SOCKET_ERROR(int) on error, *nix returns -1.
uses an const char* for the fourth parameter in setsockopt().
ioctlsocket() instead of fcntl(), this returns SOCK_ERROR(int), *nix returns -1.
ioctlsocket() has the option as a u_long, fcntl() uses an int.

Not mentioned, select() on Linux modifies the timeout value to reflect time not slept.
 */



/*
BOOL WINAPI SetupComm(
   HANDLE hFile,
   DWORD  dwInQueue,
   DWORD  dwOutQueue
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetupComm = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}*/

BOOL WINAPI GetCommState(
      HANDLE hFile,
   LPDCB  lpDCB
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"GetCommState = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI SetCommState(
   HANDLE hFile,
   LPDCB  lpDCB
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetCommState = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI FlushFileBuffers(
   HANDLE hFile
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"FlushFileBuffers = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI FreeConsole(void)
{
	dfprintf(__LINE__,__FILE__,TRACE,"FreeConsole = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI ScrollConsoleScreenBuffer(
  _In_           HANDLE     hConsoleOutput,
  _In_     const SMALL_RECT *lpScrollRectangle,
  _In_opt_ const SMALL_RECT *lpClipRectangle,
  _In_           COORD      dwDestinationOrigin,
  _In_     const CHAR_INFO  *lpFill
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"ScrollConsoleScreenBuffer = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI AllocConsole(void)
{
	dfprintf(__LINE__,__FILE__,TRACE,"AllocConsole = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

HANDLE WINAPI CreateConsoleScreenBuffer(
  _In_             DWORD               dwDesiredAccess,
  _In_             DWORD               dwShareMode,
  _In_opt_   const SECURITY_ATTRIBUTES *lpSecurityAttributes,
  _In_             DWORD               dwFlags,
  _Reserved_       LPVOID              lpScreenBufferData
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"CreateConsoleScreenBuffer = \33[1;32mNULL\33[0m\n");
	return (0);
}

BOOL WINAPI GetConsoleScreenBufferInfo(
  _In_  HANDLE                      hConsoleOutput,
  _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"GetConsoleScreenBufferInfo = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI SetConsoleTextAttribute(
  _In_ HANDLE hConsoleOutput,
  _In_ WORD   wAttributes
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetConsoleTextAttribute = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI SetConsoleScreenBufferSize(
  _In_ HANDLE hConsoleOutput,
  _In_ COORD  dwSize
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetConsoleScreenBufferSize = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI GetConsoleMode(
  _In_  HANDLE  hConsoleHandle,
  _Out_ LPDWORD lpMode
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"GetConsoleMode = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI SetConsoleMode(
  _In_ HANDLE hConsoleHandle,
  _In_ DWORD  dwMode
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetConsoleMode = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

BOOL WINAPI SetConsoleCursorPosition(
  _In_ HANDLE hConsoleOutput,
  _In_ COORD  dwCursorPosition
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetConsoleCursorPosition = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}


BOOL WINAPI WriteFile(
          HANDLE       hFile,
          LPCVOID      lpBuffer,
          DWORD        nNumberOfBytesToWrite,
     LPDWORD      lpNumberOfBytesWritten,
   LPOVERLAPPED lpOverlapped
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"WriteFile = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}

void WINAPI OutputDebugString(
   LPCTSTR lpOutputString
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"OutputDebugString = \33[1;32mNULL\33[0m\n");
	return;
}

HANDLE WINAPI GetStdHandle(
   DWORD nStdHandle
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"GetStdHandle = \33[1;32mNULL\33[0m\n");
	return (0);
}

DWORD WINAPI GetProfileString(
    LPCTSTR lpAppName,
    LPCTSTR lpKeyName,
    LPCTSTR lpDefault,
   LPTSTR  lpReturnedString,
    DWORD   nSize
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"GetProfileString = \33[1;32mNULL\33[0m\n");
	return (0);
}

DWORD WINAPI GetLastError(void)
{
	fprintf(stderr,"GetLastError = \33[1;32mNULL\33[0m\n");
	return (0);
}


BOOL WINAPI SetupComm(
   HANDLE hFile,
   DWORD  dwInQueue,
   DWORD  dwOutQueue
)
{
	dfprintf(__LINE__,__FILE__,TRACE,"SetupComm = \33[1;32mNULL\33[0m\n");
	return (FALSE);
}


#define NUMCFHANDLES	20
int numCFHandles = 0;
char *CFileHandles[NUMCFHANDLES] = { NULL };

HANDLE WINAPI CreateFile(
       LPCTSTR               lpFileName,
       DWORD                 dwDesiredAccess,
       DWORD                 dwShareMode,
   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
       DWORD                 dwCreationDisposition,
       DWORD                 dwFlagsAndAttributes,
	   JKPHANDLE                hTemplateFile
)
{
	int i;
	int newindex = 0;
	if ( numCFHandles == NUMCFHANDLES ) {
		printf ("CreateFile failed due to too many files open...\n");
		return (INVALID_HANDLE_VALUE);
	}
	numCFHandles++;
	for (i=0;i<NUMCFHANDLES;i++) {
		if(CFileHandles[i] == NULL) {
			newindex = i;
			break;
		}
	}
	CFileHandles[newindex] = (char *)malloc(strlen(lpFileName)+1);
	strcpy(CFileHandles[newindex],lpFileName);
	dfprintf(__LINE__,__FILE__,TRACE,"CreateFile handle for %s = %i\n",lpFileName,newindex+1);

	if ( dwDesiredAccess == GENERIC_READ && dwCreationDisposition != OPEN_EXISTING ) return (INVALID_HANDLE_VALUE);
	if ( dwDesiredAccess == GENERIC_WRITE && dwCreationDisposition != CREATE_NEW && dwCreationDisposition != CREATE_ALWAYS ) return (INVALID_HANDLE_VALUE);
	if ( dwDesiredAccess == (GENERIC_READ|GENERIC_WRITE) && dwCreationDisposition != OPEN_EXISTING ) {
	dfprintf(__LINE__,__FILE__,TRACE,"CreateFile COM port option is not available at this time... need more code to finish this...\n");
		return (INVALID_HANDLE_VALUE);
	}
	if ( dwDesiredAccess == GENERIC_READ ) {
		int fpin = open(lpFileName,O_RDONLY,S_IREAD);
		if ( fpin == -1 ) {
			printf("CreateFile unable to open %s for GENERIC_READ, errno = %i\n",lpFileName,errno);
			return (INVALID_HANDLE_VALUE);
		}
		close(fpin);
	}
	if ( dwDesiredAccess == GENERIC_WRITE ) {
		int fpout = open(lpFileName,O_RDWR | O_CREAT,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if ( fpout == -1 ) {
			printf("CreateFile unable to open %s for GENERIC_WRITE, errno = %i\n",lpFileName,errno);
			return (INVALID_HANDLE_VALUE);
		}
		close(fpout);
	}

	return (newindex+1);
}

#define RANGE1(x) (((x) > 63 && (x) < 96 ) ? true : false )
#define RANGE2(x) (((x) > 63 && (x) < 127 ) ? true : false )

bool StripCSI(char *ci, char *co)
{

    enum stateENUM {
      INITIAL,
      SINGLECHAR,
      TWOCHAR,
      MULTICHAR1,
      MULTICHAR2
    } state = INITIAL;

	enum OutStateENUM {
      OUTPUT,
      NOOUTPUT
    } OutState = OUTPUT;

	static char ESC='\33';

	int i = 1;
	int lenline;
	char c[2];

	lenline = strlen(ci);
	*co = '\000';

    if ( lenline == 0 ) return (true);
	c[0] = *(ci);

    while ((c[1] = *(ci+i++) ) != '\000') {
		switch (state) {

		case INITIAL:
		case SINGLECHAR:
			OutState = OUTPUT;
			if (c[0] == '\233' ) {
				state = SINGLECHAR;
				OutState = NOOUTPUT;
//				printf("<single char CSI>");
			}
			if (c[0] == ESC) {
				if ( c[1] == '[' ) {
					state = MULTICHAR1;
					OutState = NOOUTPUT;
//					printf("<multi char CSI>");
				} else if ( RANGE1(c[1]) ) {
					state = TWOCHAR;
					OutState = NOOUTPUT;
//					printf("<two char CSI>n");
				}
			} 
			break;

		case TWOCHAR:
			state = INITIAL;
			break;

		case MULTICHAR1:
			state = MULTICHAR2;
			break;

		case MULTICHAR2:
			if ( RANGE2(c[0]) ) {
				state = INITIAL;
//				printf("</multi char CSI>");
			}
			break;

		}
		
		switch (OutState) {
		
		case OUTPUT:
			*co = c[0];
			co++;
//			printf("%c", c[0] );
			break;
		case NOOUTPUT:
			break;

		}

		c[0] = c[1];
    }
	
	if (state == INITIAL) {
		*co = c[0];
		co++;
//		printf("%c", c[0] );
	}

	*co = '\000';
//	printf("\n");

	return (false);
}





/*
How MsgBox works:
	The simplest way to use MsgBox is to just call it with a single string argument. In this case,
	MsgBox will produce a message box with an "error" banner and a single "ok" button.
	The string sent to MsgBox can also contain formatting instructions. Note that not all C fprintf
	formatting is recognized (see the code below), but most of the more common ones (strings,integers,
	floats, hex, etc.) are. The call to MsgBox has a variable argument list. The arguments beyond the format
	string are assumed to be the proper kind of data associated with the formats found in the format string.
	
	  If the last two characters of the format string are special formats type "%&", then an additional
	unsigned integer argument is expected. This argument must appear before any other additional (formatting)
	arguments in the list and it will replace the default messagebox mode (MB_ICONERROR | MB_OK)
	used by MsgBox. If the "%&" mode is specified, then the global char* variable lpszMsgBoxBanner
	(found in globals.h) will be checked. If is not NULL, then the string that it points to will be used as
	the title of message box. If it is NULL, then the title of message box will be blank.
	
	  If the last two characters of the format string are special formats type "%?" or "%!", then the message is
	assumed to be a yes/no question or an informational message respectfully. For yes/no questions, the title
	bar will be set to "Select Yes or No" and the mode will be set to MB_YESNO | MB_ICONQUESTION. For informational
	messages, he title bar will be set to "Information" and the mode will be set to MB_OK | MB_ICONEXCLAMATION.
 

	MsgBox will always return the value of the return from MessageBox.

  examples:

	MsgBox("program error");
	MsgBox("program error %i", error_num);
	if ( MsgBox("Do you want some info?%?") == IDYES ) MsgBox("Here is some info: %s%!", "some info");
	lpszMsgBoxBanner = "Very Bad Error!";
	while ( MsgReturn == IDNO ) {
		MsgReturn = 
		MsgBox ("Do you wish to create the %s instructions file?%&", MB_YESNOCANCEL | MB_ICONQUESTION , "recover");
	}
	lpszMsgBoxBanner = NULL;
	if ( MsgReturn == IDCANCEL ) NumBackups--;


  Note: The default MessageBox created is modal. The global variable HWND hWnd (found in passwin.h) is always passed
		to MessageBox as the owner window. This can cause a problem if hWnd is not set to a valid window
		handle. In some cases, one may wish to create a message box before any other window has been created. To
		avoide this problem, passwin creates a message only window early on (see routine passwin.cpp). However,
		this also complicates the programming, in that we must change hWnd to point to whoever is going to be 
		the owner of error message boxes as we flow through the program... This is a lot of work, just to avoid
		needing to pass the owner window handle into MsgBox each time it is called. The goal was to keep the MsgBox
		call as simple as possible. It works great in a "normal" Windows program where a master window is opened
		up as soon as the WinMain program starts followed by a message loop. The passwin program is different: WinMain
		has no message loop; the "main" window is a dialog box.

*/





int MsgBox(const char * fmt, ... )
{
	unsigned int mode = 0;
//	bool ismode = false;
	int lastchar;
	char *p;
	char *sval;
	int ival;
	unsigned int uival;
	double dval;
#define BUFFERLEN	2000
	char buffer[BUFFERLEN];
//	buffer[0]='\000';
	char *b;
	char *saveme = NULL;
	char cTrue[] = "true";
	char cFalse[] = "false";
	int len;
	int templen;
	int iSaveReturn;

	va_list ap;
	va_start(ap, fmt);
	lastchar = strlen(fmt);
	if (lastchar > 0 ) {
		if ( fmt[lastchar-1] == '&' ) {
			mode = va_arg(ap, unsigned int);
		} 
	}
	if (lastchar == 0 ) return -1;

	b=buffer;
	if ( bTextMode ) {
		*b = ' ';
		b++;
	}
	*b = '\000';

//MessageBox( hWnd, "testing MessageBox at start of MsgBox", NULL, MB_ICONERROR | MB_OK );
    for (p = (char*)fmt; *p; p++) {         /* [1] */
        if (*p != '%') {
            *b = *p;
			b++;
            continue;                /* [2] */
        }
        switch (*++p) {
        case 'i':
            ival = va_arg(ap, int);
            len = sprintf(b, "%i", ival);
			b+=len;
            break;
        case 'f':
            dval = va_arg(ap, double);
            len = sprintf(b, "%f", dval);
			b+=len;
            break;
        case 's':
			sval = va_arg(ap, char *);
			templen = strlen(sval);
			if (templen < BUFFERLEN*8/10 || templen > 0) strncpy(b, sval, MIN(templen,BUFFERLEN*8/10));   // why is this "||" ??? should it be "&&"?
			b+=templen;
            break;
        case 'b':
			ival = va_arg(ap, int);
			if (ival) {
				templen = 4;
				if (templen < BUFFERLEN*8/10 || templen > 0) strncpy(b, cTrue, MIN(templen,BUFFERLEN*8/10));
				b+=templen;
			} else {
				templen = 5;
				if (templen < BUFFERLEN*8/10 || templen > 0) strncpy(b, cFalse, MIN(templen,BUFFERLEN*8/10));
				b+=templen;
			}
            break;
        case 'c':
            ival = va_arg(ap, int);
            len = sprintf(b, "%c", ival);
			b+=len;
            break;
        case 'd':
            ival = va_arg(ap, int);
            len = sprintf(b, "%d", ival);
			b+=len;
            break;
        case 'o':
            ival = va_arg(ap, int);
            len = sprintf(b, "%o", ival);
			b+=len;
            break;
        case 'u':
            uival = va_arg(ap, unsigned int);
            len = sprintf(b, "%u", uival);
			b+=len;
            break;
        case 'x':
            ival = va_arg(ap, int);
            len = sprintf(b, "%x", ival);
			b+=len;
            break;
        case 'X':
            ival = va_arg(ap, int);
            len = sprintf(b, "%X", ival);
			b+=len;
            break;
        case 'e':
            dval = va_arg(ap, double);
            len = sprintf(b, "%e", dval);
			b+=len;
            break;
        case 'E':
            dval = va_arg(ap, double);
            len = sprintf(b, "%E", dval);
			b+=len;
            break;
        case 'g':
            dval = va_arg(ap, double);
            len = sprintf(b, "%g", dval);
			b+=len;
            break;
        case 'G':
            dval = va_arg(ap, double);
            len = sprintf(b, "%G", dval);
			b+=len;
            break;
        case '&':
//			++p;
            break;
        case '?':
			mode = MB_YESNO | MB_ICONQUESTION;
			saveme = lpszMsgBoxBanner;
			lpszMsgBoxBanner = (char*)"Select Yes or No";
//			++p;
            break;
        case '!':
			mode = MB_OK | MB_ICONEXCLAMATION;
			saveme = lpszMsgBoxBanner;
			lpszMsgBoxBanner = (char*)"Information";
//			++p;
            break;
		case '\0':
			p--; // reverse the ++p from the header of the switch
			break;
        default:
            *b = *p;
			b++;
            break;
        }
    }

	*b = '\0';

	dfprintf(__LINE__,__FILE__,DEBUGMSGBOX,"%s\n", buffer);   // warning: can cause a loop !

//	fflush(stdout);
	
	va_end(ap);

	iSaveReturn = ErrorMessageTX( buffer, mode);
	lpszMsgBoxBanner = saveme;
	return (iSaveReturn);
}


int ReAllocateCharVector(unsigned char **p, int length)
{
	int i;
	int isize;

	if ( *p != NULL ) {
		isize = _msize( *p );
		dfprintf(__LINE__,__FILE__,DEBUGREALLOCATECHAR, "Size of block (%llx) (len=%i) before realloc: %u\n", *p, length, isize );  // warning: can cause a loop !
		if ( length == 0 ) return (isize);

   /* Reallocate and show new size: */
		i = isize + length + 1;
		if( (*p = (unsigned char*)realloc( *p, i) ) ==  NULL ) return (0);
		isize = _msize( *p );
		dfprintf(__LINE__,__FILE__,DEBUGREALLOCATECHAR, "Size of block (%llx) after realloc: %u (requested %i)\n", *p, isize ,i);  // warning: can cause a loop !
		return (isize);
	}


	*p = (unsigned char*)malloc(length+1);
	dfprintf(__LINE__,__FILE__,DEBUGREALLOCATECHAR, "Address of block (%llx) after malloc: size >= %i\n", *p, length+1 );  // warning: can cause a loop !
	if (*p != NULL) {
		for (i=0;i<length;i++){
			*(*p+i) = '\000';
		}
		return (length+1);
	}
	return (0);
}


int ErrorMessageTX(LPSTR msg, unsigned int mode) {
	int msgboxID = 0;

	if ( lpszMsgBoxBanner == NULL ) {
		msgboxID = MessageBoxTX( (const char *)msg, " ", mode );
	} else {
		msgboxID = MessageBoxTX( (const char *)msg, lpszMsgBoxBanner, mode );
	}

	return(msgboxID);
}

char * FindWordBreak (char * msg, int iLen) {
	int i;
	int iRealLen;
	if (iLen < 1) return(NULL);
	iRealLen = MIN(iLen,(int)strlen(msg));

	for (i=iRealLen-1;i>0;i--) if ( msg[i] == ' ' ) return (msg+i);

	return (msg+iRealLen-1);
}

int FormatTutMsg (const char * msg) {
#define TUTLINELEN	80
	int iNextCR;
	int iNextWorkBrk;
	char * szStartMsg;
	char szTutString[TUTLINELEN];
	char *chrptr;
	char *chrWordBrk;
	char *szNullChar;

	szStartMsg = (char *)msg;
	szNullChar = szStartMsg + strlen (szStartMsg);

	while ( szNullChar > szStartMsg ) {
		chrptr = (char *)strchrnul(szStartMsg, '\n');
		iNextCR = (chrptr - szStartMsg);
		if ( iNextCR < TUTLINELEN ) {
			strncpy(szTutString,(const char *)szStartMsg, (size_t)iNextCR);
			szTutString[iNextCR] = '\000';
		} else {
			chrWordBrk = FindWordBreak(szStartMsg, TUTLINELEN );
			iNextWorkBrk = (chrWordBrk - szStartMsg);
			strncpy(szTutString,(const char *)szStartMsg, (size_t)MIN(iNextCR,iNextWorkBrk));
			if (MIN(iNextCR,iNextWorkBrk) < TUTLINELEN) szTutString[MIN(iNextCR,iNextWorkBrk)] = '\000';
			if (MIN(iNextCR,iNextWorkBrk) == TUTLINELEN) szTutString[TUTLINELEN-1] = '\000';
		}
		tutPrintString(szTutString);
		if ( strlen(szTutString) == strlen(szStartMsg) ) break;  // avoide over indexing szStartMsg at while() test
		szStartMsg = szStartMsg + strlen(szTutString) + 1;
	}

	return 0;
}

int MessageBoxTX(const char * msg, const char * lpszBanner, unsigned int mode) {
//	int iNumArg;
	int iReply;

	if ( mode & (MB_YESNO | MB_ICONQUESTION) ) {
		FormatTutMsg(msg);
//		iNumArg = 1;
//		tutDisplayPrompt ( MESSAGE_BOX , iNumArg , "BANNER", lpszBanner);
			if ( strcmp( lpszBanner , " " ) != 0 ) tutPrintString(lpszBanner);
//		iReply = (int)tutFetchDatax2 (1);
			iReply = 1;
		if ( iReply == 1 ) return(IDYES);
		return(IDNO);
	}
	if ( mode & ( MB_OK | MB_ICONEXCLAMATION | MB_ICONERROR ) ) {
		if ( strcmp( lpszBanner , " " ) != 0 ) tutPrintString(lpszBanner);
		FormatTutMsg(msg);
		return(IDOK);
	}

// default:
	if ( strcmp( lpszBanner , " " ) != 0 ) tutPrintString(lpszBanner);
	FormatTutMsg(msg);
	return(IDOK);
}


size_t _msize(void *memblock)
{

	dfprintf(__LINE__,__FILE__,DEBUGMSIZE,"msize = %lu\n", malloc_usable_size (memblock));

	return (malloc_usable_size (memblock));
}


int tutPrintString (const char * szText){

	if (szText == NULL) return(BADUPRSTRCCALL);

	if( strlen(szText) != 0 && bIsStdinTty) {
		int iNumBytesOutput = fprintf(stdout," %s\n",szText);
		if ( iNumBytesOutput < 0 ) {
			fprintf (stderr,"print of string failed at line %i in tutPrintString",__LINE__);
			return (iNumBytesOutput);
		}
	}
		if ( strlen(szText) == 0 || !bOutputDP ) dfprintf(__LINE__,__FILE__,DEBUGTUTOR,"tutPrintString called with bOutputDP = %u and string = \"%s\" (length %i)\n",bOutputDP,szText,strlen(szText)); // warning: can cause a loop !
		if ( strlen(szText) != 0 &&  bOutputDP ) dfprintf(__LINE__,__FILE__,DEBUGTUTOR," %s\n",szText); // warning: can cause a loop !

	return(SUCCESS);
}

 
int SetUpDebugConsole(void) 
{ 
    LPSTR lpszPrompt1 = (char*)"Debug console opened for passwin";
    LPSTR lpszPrompt2 = (char*)"(keyboard input to this window is ignored)\n";
//    CHAR chBuffer[256]; 
//    DWORD cRead; 
    DWORD cWritten, fdwMode, fdwOldMode; 
    WORD wOldColorAttrs;
    COORD dwScreenBufferSize; 

	FreeConsole();

	if (!AllocConsole())
    {
        MsgBox("AllocConsole failed"); 
    }

	hConsoleBuffer = CreateConsoleScreenBuffer(
		GENERIC_READ | GENERIC_WRITE,  // access flag
		0,      // buffer share mode   can be zero | FILE_SHARE_READ | FILE_SHARE_WRITE
		NULL , // pointer to security attributes  LPSECURITY_ATTRIBUTES *lpSecurityAttributes
		CONSOLE_TEXTMODE_BUFFER,          // type of buffer to create   The only currently supported screen buffer type is CONSOLE_TEXTMODE_BUFFER.
		NULL   // reserved   LPVOID lpScreenBufferData
	);

    // Get handles to STDIN and STDOUT. 

    hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE); 
	hStderr = GetStdHandle(STD_ERROR_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE || 
        hStdout == INVALID_HANDLE_VALUE || hStderr == INVALID_HANDLE_VALUE) 
    {
        MsgBox("GetStdHandle failed");
        return 1;
    }
    // Save the current text colors. 

    if (! GetConsoleScreenBufferInfo(hConsoleBuffer, &csbiInfo)) 
    {
        MsgBox("GetConsoleScreenBufferInfo failed in SetUpDebugConsole"); 
        return 1;
    }

    wOldColorAttrs = csbiInfo.wAttributes; 

    // Set the text attributes to draw red text on black background. 

    if (! SetConsoleTextAttribute(hStderr, FOREGROUND_RED | 
            FOREGROUND_INTENSITY))
    {
        MsgBox("SetConsoleTextAttribute failed in SetUpDebugConsole"); 
        return 1;
    }

    // Set the screen buffer size to 150 columns by 250 lines. 

	dwScreenBufferSize.X = 150;
	dwScreenBufferSize.Y = 250;

    if (! SetConsoleScreenBufferSize(hStderr, dwScreenBufferSize) )
    {
        MsgBox("SetConsoleScreenBufferSize failed in SetUpDebugConsole"); 
        return 1;
    }

    // Write to STDERR by using the default 
    // modes. Input is echoed automatically, and ReadFile 
    // does not return until a carriage return is typed. 
    // 
    // The default input modes are line, processed, and echo. 
    // The default output modes are processed and wrap at EOL. 

        if (! WriteFile( 
            hStderr,               // output handle 
            lpszPrompt1,           // prompt string 
            lstrlenA(lpszPrompt1), // string length 
            &cWritten,             // bytes written 
            NULL) )                // not overlapped 
        {
            MsgBox("WriteFile failed in SetUpDebugConsole"); 
            return 1;
        }


    // Turn off the line input and echo input modes 

    if (! GetConsoleMode(hConsoleBuffer, &fdwOldMode)) 
    {
       MsgBox("GetConsoleMode failed in SetUpDebugConsole");
       return 1;
    }

    fdwMode = fdwOldMode & 
        ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT); 
    if (! SetConsoleMode(hConsoleBuffer, fdwMode)) 
    {
       MsgBox("SetConsoleMode failed in SetUpDebugConsole");
       return 1;
    }

    // ReadFile returns when any input is available.  
    // WriteFile is used to echo input. 

    NewLine();

        if (! WriteFile( 
            hStderr,               // output handle 
            lpszPrompt2,           // prompt string 
            lstrlenA(lpszPrompt2), // string length 
            &cWritten,             // bytes written 
            NULL) )                // not overlapped 
        {
            MsgBox("second WriteFile failed in SetUpDebugConsole");
            return 1;
        }
/*
        if (! ReadFile(hStdin, chBuffer, 1, &cRead, NULL)) 
            break; 
        if (chBuffer[0] == '\r')
            NewLine();
        else if (! WriteFile(hStdout, chBuffer, cRead, 
            &cWritten, NULL)) break;
        else
            NewLine();
        if (chBuffer[0] == 'q') break; 
*/
    // Restore the original console mode. 

    SetConsoleMode(hConsoleBuffer, fdwOldMode);

    // Restore the original text colors. 

    SetConsoleTextAttribute(hStderr, wOldColorAttrs);

    return 0;
}

// The NewLine function handles carriage returns when the processed 
// input mode is disabled. It gets the current cursor position 
// and resets it to the first cell of the next row. 
 
void NewLine(void) 
{ 
    if (! GetConsoleScreenBufferInfo(hConsoleBuffer, &csbiInfo)) 
    {
        MsgBox("GetConsoleScreenBufferInfo failed in NewLine");
        return;
    }

    csbiInfo.dwCursorPosition.X = 0; 

    // If it is the last line in the screen buffer, scroll 
    // the buffer up. 

    if ((csbiInfo.dwSize.Y-1) == csbiInfo.dwCursorPosition.Y) 
    { 
        ScrollScreenBuffer(hConsoleBuffer, 1); 
    } 

    // Otherwise, advance the cursor to the next line. 

    else csbiInfo.dwCursorPosition.Y += 1; 
 
    if (! SetConsoleCursorPosition(hStderr, 
        csbiInfo.dwCursorPosition)) 
    {
        MsgBox("SetConsoleCursorPosition failed in NewLine");
        return;
    }
	return;
} 

void ScrollScreenBuffer(HANDLE h, INT x)
{
    SMALL_RECT srctScrollRect, srctClipRect;
    CHAR_INFO chiFill;
    COORD coordDest;

    srctScrollRect.Left = 0;
    srctScrollRect.Top = 1;
    srctScrollRect.Right = csbiInfo.dwSize.X - (SHORT)x; 
    srctScrollRect.Bottom = csbiInfo.dwSize.Y - (SHORT)x; 
 
    // The destination for the scroll rectangle is one row up. 
 
    coordDest.X = 0; 
    coordDest.Y = 0; 
 
    // The clipping rectangle is the same as the scrolling rectangle. 
    // The destination row is left unchanged. 
 
    srctClipRect = srctScrollRect; 
 
    // Set the fill character and attributes. 
 
    chiFill.Attributes = FOREGROUND_RED|FOREGROUND_INTENSITY; 
    chiFill.Char.AsciiChar = (char)' '; 
 
    // Scroll up one line. 
 
    ScrollConsoleScreenBuffer( 
        h,               // screen buffer handle 
        &srctScrollRect, // scrolling rectangle 
        &srctClipRect,   // clipping rectangle 
        coordDest,       // top left destination cell 
        &chiFill);       // fill character and color 

	return;
}



char * jtrunwind (int icall) {
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp;
#define JTRUNWINDSIZE	100
  static char ctemp[JTRUNWINDSIZE];
  int j = 0;
  ctemp[0] = '\000';

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    unw_word_t  offset;
    char        fname[64];
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);
    fname[0] = '\0';
    unw_get_proc_name(&cursor, fname, sizeof(fname), &offset);
    if (icall < 0 ) {
	dfprintf (__LINE__,__FILE__,TRACE,"ip = %lx, sp = %lx (%s+0x%lx)\n", (long) ip, (long) sp, fname, offset);
    }
    if (icall ==  j) {
	if ( strlen( fname ) < (JTRUNWINDSIZE-23) ) {
//		strcpy ( ctemp , fname );
		snprintf ( ctemp ,JTRUNWINDSIZE-1, "%s, +0x%0lx",fname, offset);
	}
    }
    j++;
  }
  return (ctemp);
}

char * jtrbacktrace(int i)
{
    int j; 
    int nptrs;
#define BTSIZE 100
    void *buffer[BTSIZE];
    char **strings;
    static char ctemp[BTSIZE];

   nptrs = backtrace(buffer, BTSIZE);
//    printf("backtrace() returned %d addresses\n", nptrs);

   /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
       would produce similar output to the following: */

   strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

   if ( i == 0 ) for (j = 0; j < nptrs; j++)
        fprintf(stderr,"%s\n", strings[j]);

   ctemp[0] = '\000';
   if ( i > -1 && i <= nptrs ) if ( strlen( strings[i] ) < (BTSIZE-1) ) strcpy ( ctemp , strings[i] ); 
   free(strings);


   return (ctemp);
}
/*
void debug_dump_stuff_msg(const void *msg, void *x, unsigned int size)
{

	unsigned int i;
//printf(" ->x = %p\n",x);
	if ( x ) {
		dfprintf(__LINE__,__FILE__,TRACE,"dump of %s[0-%i] starting at address %p: \n", (char *)msg, size, x);
		for(i=0;i<size;i++)
		{
			dfprintf(__LINE__,__FILE__,NOHEADspecial,"%02x", ((unsigned char*)x)[i]);
			if( (i%4)==3 ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial," ");
			}
		}
		dfprintf(__LINE__,__FILE__,NOHEADspecial," ___ ");
		for(i=0;i<size;i++)
		{
			if ( isprint(((unsigned char*)x)[i]) ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial,"%c", ((unsigned char*)x)[i]);
			} else {
				dfprintf(__LINE__,__FILE__,NOHEADspecial,".");
			}
			if( (i%4)==3 ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial," ");
			}
		}
		dfprintf(__LINE__,__FILE__,NOHEADspecial,"\n");
	} else {
		dfprintf(__LINE__,__FILE__,TRACE,"%s points to NULL, dump of [0-%i] not possible!\n", (char *)msg, size);
	}

	return;
}
*/

void debug_dump_stuff_noeol_f(unsigned int line, const char * file, unsigned int debugflag, void *x, unsigned int size)
{
	unsigned int i;
	unsigned int dbflg = NOHEADspecial;

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
 
	if ( !debugCheckflags( debugflag ) ) return;
	if ( debugpointertest(x) ) {
		for(i=0;i<size;i++)
		{
//dfprintf(__LINE__,__FILE__,TRACE,"i = %i, NOHEADspecial = %i, print char at %p:\n",i , NOHEADspecial, ((unsigned char*)x)[i]);
			dfprintf(line,file,dbflg,"%02x", ((unsigned char*)x)[i]);
			if( (i%4)==3 ) {
				dfprintf(line,file,dbflg," ");
			}
		}
		dfprintf(line,file,dbflg," ___ ");
		for(i=0;i<size;i++)
		{
			if ( isprint(((unsigned char*)x)[i]) ) {
				dfprintf(line,file,dbflg,"%c", ((unsigned char*)x)[i]);
			} else {
				dfprintf(line,file,dbflg,".");
			}
			if( (i%4)==3 ) {
				dfprintf(line,file,dbflg," ");
			}
		}
	} else {
		dfprintf(line,file,dbflg,"debug_dump_fmt: bad call, argument pointer is %s\n", debugpointer2str(x));
	}

	return;
}

void debug_dump_stuff_f(unsigned int line, const char * file, unsigned int debugflag, void* x, unsigned int size)
{
	unsigned int dbflg = NOHEADspecial;

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
 
	if ( !debugCheckflags( debugflag ) ) return;

	debug_dump_stuff_noeol_f(line,file,dbflg,x,size);
	dfprintf(line,file,dbflg,"\n");
}

void debug_dump_stuff_msg_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, void *x, unsigned int size)
{
	unsigned int dbflg  = NOHEADspecial;
	unsigned int dbflg2 = NOHEADspecial;

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return;

	dfprintf(__LINE__,__FILE__,DEBUGDMPSTUFF,"debug_dump_stuff_msg_f: line = %i, file = %s, debugflag = %u, msg = %s, dbflg = %u, dbflg2 = %u\n",
									line, file, debugflag, msg, dbflg , dbflg2 );

	if ( x ) {
		dfprintf(line,file,dbflg2,"%s[0-%i] starting at address %p: \n",(char *)msg ,size ,x );
		debug_dump_stuff_f(line,file,dbflg,x , size);
	} else {
		dfprintf(line,file,dbflg2,"%s points to -nil-, dump of %s[0-%i] not possible!\n", (char *)msg, (char *)msg, size);
	}

	return;
}

void debug_dump_fmt( void *x, unsigned int size)
{
	unsigned int i;

  
	if ( debugpointertest(x) ) {
		for(i=0;i<size;i++)
		{
//dfprintf(__LINE__,__FILE__,TRACE,"i = %i, NOHEADspecial = %i, print char at %p:\n",i , NOHEADspecial, ((unsigned char*)x)[i]);
			dfprintf(__LINE__,__FILE__,NOHEADspecial,"%02x", ((unsigned char*)x)[i]);
			if( (i%4)==3 ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial," ");
			}
		}
		dfprintf(__LINE__,__FILE__,NOHEADspecial," ___ ");
		for(i=0;i<size;i++)
		{
			if ( isprint(((unsigned char*)x)[i]) ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial,"%c", ((unsigned char*)x)[i]);
			} else {
				dfprintf(__LINE__,__FILE__,NOHEADspecial,".");
			}
			if( (i%4)==3 ) {
				dfprintf(__LINE__,__FILE__,NOHEADspecial," ");
			}
		}
	} else {
		dfprintf(__LINE__,__FILE__,TRACE,"debug_dump_fmt: bad call, argument pointer is %s\n", debugpointer2str(x));
	}

	return;
}

/*
	&fmt_cuda_cryptsha512
struct fmt_main {
	struct fmt_params params;
	struct fmt_methods methods;
	struct fmt_private private;
	struct fmt_main *next;
};
struct fmt_params {
	char *label;
	char *format_name;
	char *algorithm_name;
	char *benchmark_comment;
	int benchmark_length;
	int plaintext_min_length;
	int plaintext_length;
	int binary_size;
	int binary_align;
	int salt_size;
	int salt_align;
	int min_keys_per_crypt;
	int max_keys_per_crypt;
	unsigned int flags;
	char *tunable_cost_name[FMT_TUNABLE_COSTS];
	char *signature[FMT_SIGNATURES];
	struct fmt_tests *tests;
};

struct fmt_tests {
	char *ciphertext, *plaintext;
	char *fields[10];
};


struct fmt_methods {
	void (*init)(struct fmt_main *self);
	void (*done)(void);
	void (*reset)(struct db_main *db);
	char *(*prepare)(char *fields[10], struct fmt_main *self);
	int (*valid)(char *ciphertext, struct fmt_main *self);
	char *(*split)(char *ciphertext, int index, struct fmt_main *self);
	void *(*binary)(char *ciphertext);
	void *(*salt)(char *ciphertext);
	unsigned int (*tunable_cost_value[FMT_TUNABLE_COSTS])(void *salt);
	char *(*source)(char *source, void *binary);
	int (*binary_hash[PASSWORD_HASH_SIZES])(void *binary);
	int (*salt_hash)(void *salt);
	int (*salt_compare)(const void *x, const void *y);
	void (*set_salt)(void *salt);
	char *(*get_key)(int index);
	void (*clear_keys)(void);
	int (*crypt_all)(int *count, struct db_salt *salt);
	int (*get_hash[PASSWORD_HASH_SIZES])(int index);
	int (*cmp_all)(void *binary, int count);
	int (*cmp_one)(void *binary, int index);
	int (*cmp_exact)(char *source, int index);
};

struct fmt_private {
	int initialized;
	void *data;
}; */
int debugdmpfmt_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct fmt_main *fmt_cuda_cryptsha512, const char * fmt_main_lable)
{
	int i;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", fmt_main_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, fmt_main_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);
	dfprintf(line,file,dbflg,".params.label                = %s\n",fmt_cuda_cryptsha512->params.label);
	dfprintf(line,file,dbflg,".params.format_name          = %s\n",fmt_cuda_cryptsha512->params.format_name);
	dfprintf(line,file,dbflg,".params.algorithm_name       = %s\n",fmt_cuda_cryptsha512->params.algorithm_name);
	dfprintf(line,file,dbflg,".params.benchmark_comment    = %s\n",fmt_cuda_cryptsha512->params.benchmark_comment);
	dfprintf(line,file,dbflg,".params.benchmark_length     = %i\n",fmt_cuda_cryptsha512->params.benchmark_length);
	dfprintf(line,file,dbflg,".params.plaintext_min_length = %i\n",fmt_cuda_cryptsha512->params.plaintext_min_length);
	dfprintf(line,file,dbflg,".params.plaintext_length     = %i\n",fmt_cuda_cryptsha512->params.plaintext_length);
	dfprintf(line,file,dbflg,".params.binary_size          = %i\n",fmt_cuda_cryptsha512->params.binary_size);
	dfprintf(line,file,dbflg,".params.salt_size            = %i\n",fmt_cuda_cryptsha512->params.salt_size);
	dfprintf(line,file,dbflg,".params.salt_align           = %i\n",fmt_cuda_cryptsha512->params.salt_align);
	dfprintf(line,file,dbflg,".params.min_keys_per_crypt   = %i\n",fmt_cuda_cryptsha512->params.min_keys_per_crypt);
	dfprintf(line,file,dbflg,".params.flags                = 0x%08x\n",fmt_cuda_cryptsha512->params.flags);
	for(i=0;i<FMT_TUNABLE_COSTS;i++) {
		if(fmt_cuda_cryptsha512->params.tunable_cost_name[i]) dfprintf(line,file,dbflg,".params.tunable_cost_name[%i] = %s\n",i,fmt_cuda_cryptsha512->params.tunable_cost_name[i]);
	}
	for(i=0;i<FMT_SIGNATURES;i++) {
		if(fmt_cuda_cryptsha512->params.signature[i]) dfprintf(line,file,dbflg,".params.signature[%i]         = %s\n",i,fmt_cuda_cryptsha512->params.signature[i]);
	}
	if(fmt_cuda_cryptsha512->params.tests) {
		dfprintf(line,file,dbflg,".params.fmt_tests.ciphertext = %s\n",fmt_cuda_cryptsha512->params.tests->ciphertext);
		dfprintf(line,file,dbflg,".params.fmt_tests.plaintext  = %s\n",fmt_cuda_cryptsha512->params.tests->plaintext);
		for(i=0;i<10;i++) {
			if(fmt_cuda_cryptsha512->params.tests->fields[i]) dfprintf(line,file,dbflg,".params.fmt_tests.fields[%i]          = %s\n",i,fmt_cuda_cryptsha512->params.tests->fields[i]);
		}
	}

	dfprintf(line,file,dbflg,".methods.init = %p\n",fmt_cuda_cryptsha512->methods.init);
	dfprintf(line,file,dbflg,".methods.done = %p\n",fmt_cuda_cryptsha512->methods.done);
	dfprintf(line,file,dbflg,".methods.reset = %p\n",fmt_cuda_cryptsha512->methods.reset);
	dfprintf(line,file,dbflg,".methods.prepare = %p\n",fmt_cuda_cryptsha512->methods.prepare);
	dfprintf(line,file,dbflg,".methods.valid = %p\n",fmt_cuda_cryptsha512->methods.valid);
	dfprintf(line,file,dbflg,".methods.split = %p\n",fmt_cuda_cryptsha512->methods.split);
	dfprintf(line,file,dbflg,".methods.binary = %p\n",fmt_cuda_cryptsha512->methods.binary);
	dfprintf(line,file,dbflg,".methods.salt = %p\n",fmt_cuda_cryptsha512->methods.salt);
	for(i=0;i<FMT_TUNABLE_COSTS;i++) {
		if(fmt_cuda_cryptsha512->methods.tunable_cost_value[i]) dfprintf(line,file,dbflg,".methods.tunable_cost_value[i] = %p\n",i,fmt_cuda_cryptsha512->methods.tunable_cost_value[i]);
	}
	dfprintf(line,file,dbflg,".methods.source = %p\n",fmt_cuda_cryptsha512->methods.source);
	for(i=0;i<PASSWORD_HASH_SIZES;i++) {
		dfprintf(line,file,dbflg,".methods.binary_hash[%i] = %p\n",i,fmt_cuda_cryptsha512->methods.binary_hash[i]);
	}
	dfprintf(line,file,dbflg,".methods.salt_hash = %p\n",fmt_cuda_cryptsha512->methods.salt_hash);
	dfprintf(line,file,dbflg,".methods.salt_compare = %p\n",fmt_cuda_cryptsha512->methods.salt_compare);
	dfprintf(line,file,dbflg,".methods.set_salt = %p\n",fmt_cuda_cryptsha512->methods.set_salt);
	dfprintf(line,file,dbflg,".methods.get_key = %p\n",fmt_cuda_cryptsha512->methods.get_key);
	dfprintf(line,file,dbflg,".methods.clear_keys = %p\n",fmt_cuda_cryptsha512->methods.clear_keys);
	dfprintf(line,file,dbflg,".methods.crypt_all = %p\n",fmt_cuda_cryptsha512->methods.crypt_all);
	for(i=0;i<PASSWORD_HASH_SIZES;i++) {
		dfprintf(line,file,dbflg,".methods.get_hash[%i] = %p\n",i,fmt_cuda_cryptsha512->methods.get_hash[i]);
	}
	dfprintf(line,file,dbflg,".methods.cmp_all = %p\n",fmt_cuda_cryptsha512->methods.cmp_all);
	dfprintf(line,file,dbflg,".methods.cmp_one = %p\n",fmt_cuda_cryptsha512->methods.cmp_one);
	dfprintf(line,file,dbflg,".methods.cmp_exact = %p\n",fmt_cuda_cryptsha512->methods.cmp_exact);

	return 0;
}

/*
struct db_main {
	int loaded;
	size_t pw_size, salt_size;
	struct db_options *options;
	struct db_salt *salts;
	struct db_salt **salt_hash;
	struct db_password **password_hash;
	int (*password_hash_func)(void *binary);
	struct db_cracked **cracked_hash;
	struct list_main *plaintexts;
	int salt_count, password_count, guess_count;
#ifndef BENCH_BUILD
	unsigned int min_cost[FMT_TUNABLE_COSTS];
	unsigned int max_cost[FMT_TUNABLE_COSTS];
#endif
	struct fmt_main *format;
	struct db_main *real;
};

struct db_options {
	unsigned int flags;
	struct list_main *users, *groups, *shells;
	int min_pps, max_pps;
#ifndef BENCH_BUILD
	unsigned int min_cost[FMT_TUNABLE_COSTS];
	unsigned int max_cost[FMT_TUNABLE_COSTS];
#endif
	int showuncracked;
	int showtypes;
	int showinvalid;
	char field_sep_char;
	int log_passwords;
};

struct list_main {
	struct list_entry *head, *tail;
	int count;
};

struct list_entry {
	struct list_entry *next;
	char data[1];
};

struct db_salt {
	struct db_salt *next;
	void *salt;
	uint32_t salt_md5[4];
	unsigned int *bitmap;
	int (*index)(int index);
	struct db_password *list;
	struct db_password **hash;
	int hash_size;
	int count;
	int sequential_id;
#ifndef BENCH_BUILD
	unsigned int cost[FMT_TUNABLE_COSTS];
#endif
	struct db_keys *keys;
};

struct db_password {
	struct db_password *next;
	void *binary;
	struct db_password *next_hash;
	char *source;
	char *login;
	char *uid;
	struct list_main *words;
};

struct db_keys {
	struct db_keys_hash *hash;
	char *ptr;
	int count;
	int count_from_guesses;
	int have_words;
	int rule;
	int lock;
	char buffer[1];
};

struct db_keys_hash {
	short hash[SINGLE_HASH_SIZE];
	struct db_keys_hash_entry list[1];
};

struct db_keys_hash_entry {
	short next;
	unsigned short offset;
};

struct db_keys_hash {
	short hash[SINGLE_HASH_SIZE];
	struct db_keys_hash_entry list[1];
};

struct db_keys_hash_entry {
	short next;
	unsigned short offset;
};

struct db_keys {
	struct db_keys_hash *hash;
	char *ptr;
	int count;
	int count_from_guesses;
	int have_words;
	int rule;
	int lock;
	char buffer[1];
}

struct db_cracked {
	struct db_cracked *next;
	char *ciphertext, *plaintext;
};

struct list_main {
	struct list_entry *head, *tail;
	int count;
};

struct list_entry {
	struct list_entry *next;
	char data[1];
};
*/
static int numdebugdmpdb_main_reent = 0;

int debugdmpdb_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_main *db, const char * db_main_lable)
{
	int i;
#define	DEBUGSTEMPLEN	100
	char stemp[DEBUGSTEMPLEN];
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if(numdebugdmpdb_main_reent > 2) {
		dfprintf(line,file,dbflg,"permitted number of re-entrant calls to debugdmpdb_main exceeded. real db_main not found... \n");	
		return 1;	// debugdmpdb_main is re-entrant (see "real db" check below). limit the number of re-entrant calls to 2
	}
	numdebugdmpdb_main_reent++;

	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", db_main_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, db_main_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);
	dfprintf(line,file,dbflg,".loaded                = %i\n",db->loaded);
	dfprintf(line,file,dbflg,".pw_size               = %i\n",db->pw_size);
	dfprintf(line,file,dbflg,".salt_size             = %i\n",db->salt_size);

	debugdmpdb_options2(dbflg,"",db->options, ".options");

	if ( db->salts ) {
		debugdmpdb_salt2(dbflg,"",db->salts, db, ".salts");
	}
	debugdmpdb_salt2(dbflg,"",(struct db_salt *)&(db->salt_hash), db, ".salt_hash");
	
//	debugdmpdb_password((struct db_password *)&(db->password_hash), ".password_hash");
	dfprintf(line,file,dbflg,".password_hash_func  = %p\n",db->password_hash_func);
//	if ( db->cracked_hash ) debugdmpdb_cracked((struct db_cracked *)&(db->cracked_hash), ".cracked_hash");
	dfprintf(line,file,dbflg,"db->cracked_hash   = %p\n",db->cracked_hash);	
	if ( db->cracked_hash ) for(i=0;i<CRACKED_HASH_SIZE;i++) {
		dfprintf(line,file,dbflg,"db->cracked_hash[%i]   = %p\n",i,db->cracked_hash[i]);	
		if (db->cracked_hash[i]) {
			dfprintf(line,file,dbflg,"*(db->cracked_hash[%i])   = 0x%08x\n",i,*(db->cracked_hash[i]));
			snprintf(stemp,DEBUGSTEMPLEN,"db->cracked_hash[%i]",i);
			debugdmpdb_cracked2(dbflg,"",db->cracked_hash[i], stemp);
		}
	}
	if (db->plaintexts) debugdmplist_main2(dbflg,"",db->plaintexts, "db->plaintexts");
	dfprintf(line,file,dbflg,"db->salt_count       = %i\n",db->salt_count);	
	dfprintf(line,file,dbflg,"db->salt_count       = %i\n",db->salt_count);	
	dfprintf(line,file,dbflg,"db->password_count   = %i\n",db->password_count);	
#ifndef BENCH_BUILD
	for(i=0;i<FMT_TUNABLE_COSTS;i++) {
		dfprintf(line,file,dbflg,"db->min_cost[%i]       = %u\n",i,db->min_cost[i]);
		dfprintf(line,file,dbflg,"db->max_cost[%i]       = %u\n",i,db->max_cost[i]);
	}
#endif
	debugdmpfmt_main2(dbflg,"", db->format, "db->format");
	if ((db->real)) {
		dfprintf(line,file,dbflg,"db->real   = (%p) .. am i real? -> %s !\n",db->real,debugstf(db == db->real)); 
		if ( !(db->real == db) ) {
			dfprintf(line,file,dbflg,"dumping db->real... \n");	 
			debugdmpdb_main2(dbflg,"", db->real, "db->real");
		}
	}	
	else dfprintf(line,file,dbflg,"db->real   = (%p) .. am i real? -> no ! ... and there is NO real db !!!\n",db->real);	

	numdebugdmpdb_main_reent--;
	numdebugdmpdb_main_reent = MAX(numdebugdmpdb_main_reent, 0);
	return(0);
}

int debugdmpdb_options_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_options *optionsdb, const char * db_options_lable)
{
	int i;
	struct list_entry *listentry;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", db_options_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, db_options_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);

	dfprintf(line,file,dbflg,"%s.flags         = 0x%08x\n",db_options_lable,optionsdb->flags);
	dfprintf(line,file,dbflg,"%s.users.count   = %i\n",db_options_lable,optionsdb->users->count);
	listentry = optionsdb->users->head;
	i = 0;
	if ( listentry ) do {
		dfprintf(line,file,dbflg,"%s.users[%i]     = %s\n",db_options_lable,i,listentry->data);
		i++;
	} while (( listentry = listentry->next));
	dfprintf(line,file,dbflg,"(listentry == db->options->users->tail) ? -> %s\n",db_options_lable,debugstf(listentry == optionsdb->users->tail));

	dfprintf(line,file,dbflg,"%s.groups.count   = %i\n",db_options_lable,optionsdb->groups->count);
	listentry = optionsdb->groups->head;
	i = 0;
	if ( listentry ) do {
		dfprintf(line,file,dbflg,"%s.groups[%i]     = %s\n",db_options_lable,i,listentry->data);
		i++;
	} while (( listentry = listentry->next));
	dfprintf(line,file,dbflg,"(listentry == db->options->groups->tail) ? -> %s\n",db_options_lable,debugstf(listentry == optionsdb->groups->tail));

	dfprintf(line,file,dbflg,"%s.shells.count   = %i\n",db_options_lable,optionsdb->shells->count);
	listentry = optionsdb->shells->head;
	i = 0;
	if ( listentry ) do {
		dfprintf(line,file,dbflg,"%s.shells[%i]     = %s\n",db_options_lable,i,listentry->data);
		i++;
	} while (( listentry = listentry->next));
	dfprintf(line,file,dbflg,"(listentry == db->options->shells->tail) ? -> %s\n",db_options_lable,debugstf(listentry == optionsdb->shells->tail));

	dfprintf(line,file,dbflg,"%s.min_pps       = %i\n",db_options_lable,optionsdb->min_pps);
	dfprintf(line,file,dbflg,"%s.max_pps       = %i\n",db_options_lable,optionsdb->max_pps);
#ifndef BENCH_BUILD
	for(i=0;i<FMT_TUNABLE_COSTS;i++) {
		dfprintf(line,file,dbflg,"%s.min_cost[%i] = %u\n",db_options_lable,i,optionsdb->min_cost[i]);
	}
	for(i=0;i<FMT_TUNABLE_COSTS;i++) {
		dfprintf(line,file,dbflg,"%s.max_cost[%i] = %u\n",db_options_lable,i,optionsdb->max_cost[i]);
	}
#endif
	dfprintf(line,file,dbflg,"%s.showuncracked  = %i\n",db_options_lable,optionsdb->showuncracked);
	dfprintf(line,file,dbflg,"%s.showtypes      = %i\n",db_options_lable,optionsdb->showtypes);
	dfprintf(line,file,dbflg,"%s.showinvalid    = %i\n",db_options_lable,optionsdb->showinvalid);
	dfprintf(line,file,dbflg,"%s.field_sep_char = %c\n",db_options_lable,optionsdb->field_sep_char);
	dfprintf(line,file,dbflg,"%s.log_passwords  = %i\n",db_options_lable,optionsdb->log_passwords);

	return(0);
}

int debugdmpdb_salt_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_salt *dbsalt, struct db_main *db, const char * db_salt_lable)
{

	struct db_password *pw;
	struct db_password *hs;
	struct db_keys *key;
	struct db_keys_hash *kehash;

	size_t bitmap_size, size, hash_size;
	int (*hash_func)(void *binary);
	int ihash;
	int i,j;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", db_salt_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, db_salt_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);

	j = 0;
	if ( dbsalt ) do {
		j++;
		dfprintf(line,file,dbflg,"%s.salt  = 0x%08x\n",db_salt_lable,dbsalt->salt);
		for(i=0;i<4;i++) {
			dfprintf(line,file,dbflg,"%s.salt_md5[%i] = %u\n",db_salt_lable,i,dbsalt->salt_md5[i]);
		}
		if ( ! ( dbsalt->hash_size < 0 ) ) {
			bitmap_size = password_hash_sizes[dbsalt->hash_size];
			size = (bitmap_size + sizeof(*dbsalt->bitmap) * 8 - 1) / (sizeof(*dbsalt->bitmap) * 8) * sizeof(*dbsalt->bitmap);
			debug_dump_stuff_msg(".salts.bitmap", dbsalt->bitmap, MIN(size,80));	
		}
		dfprintf(line,file,dbflg,"%s.bitmap  = 0x%08x\n",db_salt_lable,dbsalt->bitmap);
		dfprintf(line,file,dbflg,"%s.index  = %p\n",db_salt_lable,dbsalt->index);
//		if ( !dbsalt->salt ) return(1);
		if ( !debugpointertest(dbsalt->list) ) {
			fprintf(stderr," dbsalt->list pointer is bad (%s)\n",debugpointer2str(dbsalt->list));
			return(1);
		}
//fprintf(stderr," in debugdmpdb_salt_f, dbflg = %i\n",dbflg);
	 	debugdmpdb_password2(dbflg,"",dbsalt->list, ".list");  
 	//      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  //////////////bombs/////////////////////
//fprintf(stderr," back in debugdmpdb_salt_f, dbflg = %i\n",dbflg);
		if ( ! ( dbsalt->hash_size < 0 ) ) {
			hash_size = bitmap_size >> PASSWORD_HASH_SHR;
			if (hash_size > 1) {
				size = hash_size * sizeof(struct db_password *);
				debug_dump_stuff_msg(".salts.hash", dbsalt->hash, MIN(size,80));
			}
		}
		dfprintf(line,file,dbflg,"%s.hash_size  = %i\n",db_salt_lable,dbsalt->hash_size);
		if ( !(dbsalt->hash_size < 0) ) {
			hs = *(dbsalt->hash);
			if ( !debugpointertest(hs) ) {
				fprintf(stderr," dbsalt->hash pointer is bad (%s)\n",debugpointer2str(hs));
				return(1);
			}
			debugdmpdb_password2(dbflg,"",hs, ".hash");   //   //////////////bombs if previous pw2 call removed /////////////////////
	//		if ( hs ) do {
	//			dfprintf(line,file,dbflg,"%s.hash.binary  = 0x%08x\n",db_salt_lable,hs->binary);
	//			if (hs->next_hash) dfprintf(line,file,dbflg,"%s.hash.next_hash  = 0x%08x\n",db_salt_lable,hs->next_hash);
	//			dfprintf(line,file,dbflg,"%s.hash.source  = %s\n",db_salt_lable,hs->source);
	//			dfprintf(line,file,dbflg,"%s.hash.login  = %s\n",db_salt_lable,hs->login);
	//			dfprintf(line,file,dbflg,"%s.hash.uid  = %s\n",db_salt_lable,hs->uid);
	//			dfprintf(line,file,dbflg,"%s.hash.words.count   = %i\n",db_salt_lable,hs->words->count);
	//			listentry = hs->words->head;
	//			i = 0;
	//			if ( listentry ) do {
	//				dfprintf(line,file,dbflg,"%s.hash.words[%i]     = %s\n",db_salt_lable,i,listentry->data);
	//				i++;
	//			} while (( listentry = listentry->next));
	//			dfprintf(line,file,dbflg,"(listentry == salts->hash->words->tail) ? -> %s\n",db_salt_lable,debugstf(listentry == hs->words->tail));
	//		} while (( hs = hs->next));
			if ( (dbsalt->count > 0) && (pw = dbsalt->list) && db ) do {
				hash_func = db->format->methods.binary_hash[dbsalt->hash_size];
				ihash = hash_func(pw->binary);
				hash_size = bitmap_size >> PASSWORD_HASH_SHR;
				if (hash_size > 1) {
					ihash >>= PASSWORD_HASH_SHR;
					debug_dump_stuff_msg(".salts.hash[i]", dbsalt->hash[ihash], MIN(hash_size,80));
				} 
			} while ((pw = pw->next));
		}
		dfprintf(line,file,dbflg,"%s.count  = %i\n",db_salt_lable,dbsalt->count);
		dfprintf(line,file,dbflg,"%s.sequential_id  = %i\n",db_salt_lable,dbsalt->sequential_id);
#ifndef BENCH_BUILD
		for(i=0;i<FMT_TUNABLE_COSTS;i++) {
			dfprintf(line,file,dbflg,"%s.cost[%i] = %u\n",db_salt_lable,i,dbsalt->cost[i]);
		}
#endif
		if ( (key = dbsalt->keys) ) {
			kehash = key->hash;
			for(i=0;i<SINGLE_HASH_SIZE;i++) {
				if ( kehash->hash[i] != 4294967295U ) {
					dfprintf(line,file,dbflg,"%s.keys.hash[%i] = %u\n",db_salt_lable,i,kehash->hash[i]);
				}
			}
////////////////////////////////////    i am here....    how do the hashes get stored ??
		} else {
			dfprintf(line,file,dbflg,"%s.keys    = %p\n",db_salt_lable,key);
		}
	} while (( dbsalt = dbsalt->next));

	return(0);
}

int debugdmpdb_password_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_password *pw, const char * db_pw_lable)
{
	int i;
	struct list_entry *listentry;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", db_pw_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, db_pw_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);

	if ( pw ) do {
		dfprintf(line,file,dbflg,"%s.binary  = 0x%08x\n",db_pw_lable,pw->binary);
		if (pw->next_hash) { dfprintf(line,file,dbflg,"%s.next_hash  = 0x%08x\n",db_pw_lable,pw->next_hash); }
			else dfprintf(line,file,dbflg,"%s.next_hash  = %p\n",db_pw_lable,pw->next_hash);
		if (pw->source) { dfprintf(line,file,dbflg,"%s.source  = %s\n",db_pw_lable,pw->source); }
			else dfprintf(line,file,dbflg,"%s.source  = %p\n",db_pw_lable,pw->source);
		if (pw->login) { dfprintf(line,file,dbflg,"%s.login  = %s\n",db_pw_lable,pw->login); }
			else dfprintf(line,file,dbflg,"%s.login  = %p\n",db_pw_lable,pw->login);
//		if (pw->uid) { dfprintf(line,file,dbflg,"%s.uid  = %s\n",db_pw_lable,pw->uid); }
		if (pw->uid) { dfprintf(line,file,dbflg,"%s.uid  = ",db_pw_lable); 
				debug_dump_fmt( pw->uid, 4);
				Dbgdmpprintf("\n"); 
			 }
			else dfprintf(line,file,dbflg,"%s.uid  = %p\n",db_pw_lable,pw->uid); 
		dfprintf(line,file,dbflg,"%s.words.count   = %i\n",db_pw_lable,pw->words->count);
		if ( !(listentry = pw->words->head) ) dfprintf(line,file,dbflg,"%s.words.head  = %p\n",db_pw_lable,listentry);
		i = 0;
		if ( listentry ) do {
			dfprintf(line,file,dbflg,"%s.words[%i]     = %s\n",db_pw_lable,i,listentry->data);
			i++;
		} while (( listentry = listentry->next));
	} while (( pw = pw->next));

	return(0);
}

int debugdmpdb_cracked_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_cracked *dbcrk, const char * db_crk_lable)
{
	struct db_cracked *dbc;
	int i = 0;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of \33[1;32m%s\33[0m from %s:\n", db_crk_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of \33[1;32m%s\33[0m from %s:\n", msg, db_crk_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);

	if ( (dbc = dbcrk ) ) do {
		dfprintf(line,file,dbflg,"%s.ciphertext[%i]  = %s\n",db_crk_lable,i,dbc->ciphertext);
		dfprintf(line,file,dbflg,"%s.plaintext[%i]  = %s\n",db_crk_lable,i,dbc->plaintext);
		i++;
	} while (( dbc = dbc->next));

	return(0);
}

int debugdmplist_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct list_main *main, const char * list_main_lable)
{
	struct list_entry *listentry;
	int i = 0;
	unsigned int dbflg  = NOHEADspecial;	// for lines of data
	unsigned int dbflg2 = NOHEADspecial;	// for header line

	if ( debugflag <  HEADUNCOND    ) dbflg += debugflag;
	if ( debugflag == HEADUNCOND    ) dbflg  = NOHEADspecial;
	if ( debugflag >= NOHEADspecial ) dbflg  = debugflag;
	if ( debugflag <= HEADUNCOND    ) dbflg2 = debugflag;
	if ( debugflag >  NOHEADspecial ) dbflg2 -= debugflag;

	if ( !debugCheckflags( debugflag ) ) return(0);
	if ( strlen(msg) == 0 ) {
		dfprintf(line,file,dbflg2,"dump of %s from %s:\n", list_main_lable, jtrunwind(1));
	} else if ( *(char *)(msg+(strlen(msg)-1)) == ':' ) {
		dfprintf(line,file,dbflg2,"%s dump of %s from %s:\n", msg, list_main_lable, jtrunwind(1));
	} else  dfprintf(line,file,dbflg2,"%s", msg);

	listentry = main->head;
	if ( listentry ) do {
		dfprintf(line,file,dbflg,"%s.data[%i]     = %s\n",list_main_lable,i,listentry->data);
		i++;
	} while (( listentry = listentry->next));

	return(0);
}

char * debugpointer2str ( void *x )
{
#define MAXDP2STR	20
	static char msg[MAXDP2STR];
	static char isnil[] = "-nil-";
	static char iswildl[] = "-wild low-";
	static char iswildh[] = "-wild high-";
	intptr_t uP1;

	uP1 = (intptr_t)x;

//	dfprintf(__LINE__,__FILE__,TRACE,"debugpointertest called from %s: x -> 0x%016lx\n",jtrunwind(1),uP1);

	if ( uP1 == 0 ) return(isnil);	// -nil- pointer (bad boy)
	debug_read_proc_file(0);	// get current heap and stack limits
	if (  uP1 < debugheapend ) {
		snprintf(msg, MAXDP2STR, "0x%016lx", uP1);
		return(msg);	// pointer less than end of heap (good boy)
	}
	if ( uP1 > debugstackend ) return(iswildh);	// pointer above end of syack (bad boy)
	if ( uP1 > debugstackstart ) {
		snprintf(msg, MAXDP2STR, "0x%016lx", uP1);
		return(msg);	// pointer less than end of stack and above start of stack (good boy)
	}

	return (iswildl);	// pointer above end of heap and below start of stack (bad boy)

}

int debugpointertest ( void *x )
{				// this code only works on linux...
	intptr_t uP1;

	uP1 = (intptr_t)x;
//	dfprintf(__LINE__,__FILE__,TRACE,"debugpointertest called from %s: x -> 0x%016lx\n",jtrunwind(1),uP1);
	if ( uP1 == 0 ) return (0);	// -nil- pointer (bad boy)
	debug_read_proc_file(0);	// get current heap and stack limits
	if (  uP1 < debugheapend ) return(-1);	// pointer less than end of heap (good boy)
	if ( uP1 > debugstackend ) return(0);	// pointer above end of syack (bad boy)
	if ( uP1 > debugstackstart ) return(1);	// pointer less than end of stack and above start of stack (good boy)

	return (0);	// pointer above end of heap and below start of stack (bad boy)
}

int debugCheckflags( unsigned int debugflag )
{
	if ( !bMyWay ) return(0);
	if ( debugflag == 0 ) return(0);
	if ( debugflag == HEADUNCOND ) return(1); 
	if ( ( debugflag > NUMDEBUGFLAGS && debugflag < HEADUNCOND ) || debugflag > ( NOHEADspecial + NUMDEBUGFLAGS ) ) {
		MsgBox("debugCheckflags failed, \"%u\" is not a valid debug flag number\n debug flag numbers must be less than %u",debugflag,NUMDEBUGFLAGS);
		if ( ! bdebug_flag_set[BMYWAYOVERRIDE] ) bMyWay=FALSE;
		return(0);
	}
	if ( debugflag < HEADUNCOND ) {
		if ( bdebug_flag_set[debugflag] ) return(1);
	}
	if ( debugflag > NOHEADspecial ) {
		if ( bdebug_flag_set[debugflag-NOHEADspecial] ) return(1);
	}

	return (0);
}

#endif // DEBUG - nukes entire module for non-DEBUG compiles
