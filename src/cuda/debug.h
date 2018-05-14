#ifndef _JOHN_DEBUG_H
#define _JOHN_DEBUG_H

#ifdef DEBUG

//#include "../options.h"

#ifndef DEBUGMAIN
#define EXTERN		extern
#define INITIZERO
#define INITSZERO
#define INITBOOLFALSE
#define INITBOOLTRUE
#define INITNULL
#define INITNEGDONE
#else
#define EXTERN
#define INITIZERO	=0
#define INITSZERO	={0}
#define INITBOOLFALSE	=false
#define INITBOOLTRUE	=true
#define INITNULL	=NULL
#define INITNEGDONE	=-1
#endif


// functions
EXTERN int debug_init ();
EXTERN void load_debug ();
EXTERN void debug_close ();
EXTERN "C" int Dbgprintf(int linenum, const char * modulename, unsigned int debugflag, const char * fmt,...);
	

// types
	

// variables

// If ColorDebug is set to true (non-zero), the debug output device is assumed to interpret ansi escape
// codes and debug output will be colorized.
// If ColorDebug is zero (default) no ansi escape sequences will be sent to the debug output device.
EXTERN int ColorDebug INITIZERO;
#endif
// define debug option indecies
#define	NONE	0
#define	NEVER	0
#define OFF	0
#define NOHEADspecial	99999
#define TRACE			1
#define DEBUGTUTOR		2
#define DEBUGMSIZE		3
#define DEBUGMSGBOX		4
#define DEBUGREALLOCATECHAR	5
#define DEBUGOPENTCPPORT	6
#define DEBUGSAVEINSTRING	7
#define DEBUGDBGPRINTF		8
#define DEBUGDUMPRAMFILE	9
#define TRACE2			10
#define DEBUGDYNASALT		11
#define DEBUGSALTDUMP		12
#define DEBUGCUDAMEMCOPY	13
#define DEBUGPROCFILE		14 
#define TRACECUDA		15 


#ifdef DEBUG
// define dfprintf command
//#define dfprintf if ( options.debug_level > NONE ) Dbgprintf
#define dfprintf if ( 1 > NONE ) Dbgprintf

// define the size of the debug option arrays
#define NUMDEBUGFLAGS	17
// define debug option names (should set to same as index define name)
#ifndef DEBUGMAIN
EXTERN const char *debug_flag[NUMDEBUGFLAGS];
#else
const char *debug_flag[NUMDEBUGFLAGS] = {
	"none", \
	"TRACE", \
	"DEBUGTUTOR", \
	"DEBUGMSIZE", \
	"DEBUGMSGBOX", \
	"DEBUGREALLOCATECHAR", \
	"DEBUGOPENTCPPORT", \
	"DEBUGSAVEINSTRING", \
	"DEBUGDBGPRINTF", \
	"DEBUGDUMPRAMFILE", \
	"TRACE2", \
	"DEBUGDYNASALT", \
	"DEBUGSALTDUMP", \
	"DEBUGCUDAMEMCOPY", \
	"DEBUGPROCFILE", \
	"TRACECUDA", \
	""};
#endif
// define the debug option status flags
EXTERN unsigned char bdebug_flag_set[NUMDEBUGFLAGS] INITSZERO;

#else   //    else !DEBUG
// create dummy dfprintf command for non-debug compiles
#define dfprintf if (0) ((int (*)(int, ...)) 0)

#endif  //    fi DEBUG
#endif  //    fi _JOHN_DEBUG_H
