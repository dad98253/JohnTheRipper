#ifndef _JOHN_DEBUG_H
#define _JOHN_DEBUG_H

#ifdef DEBUG

#ifndef CUDAKERNEL
#include <malloc.h>
#include "options.h"
#include "formats.h"
#define CCALLING
#define DBGLVLTEST	debugVirbosity
#else
#define CCALLING	"C"
#define DBGLVLTEST	debugVirbosity
#endif

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

#ifndef CUDAKERNEL
#if __linux__   //  or #if __GNUC__
    #if __x86_64__ || __ppc64__
        #define DEBUGENVIRONMENT64
    #else
        #define DEBUGENVIRONMENT32
    #endif
#else
    #if _WIN32
        #define DEBUGENVIRONMENT32
    #else
        #define DEBUGENVIRONMENT64
    #endif
#endif // __linux__
#endif

// functions
EXTERN CCALLING int debug_init ();
EXTERN CCALLING void load_debug ();
EXTERN CCALLING void debug_close ();
EXTERN CCALLING int Dbgprintf(int linenum, const char * modulename, unsigned int debugflag, const char * fmt,...);
EXTERN CCALLING int Dbgdmpprintf( const char * fmt,...);
EXTERN CCALLING char * jtrbacktrace(int i);
EXTERN CCALLING char * jtrunwind (int icall);
EXTERN CCALLING int debug_read_proc_file(int idumpem);
EXTERN CCALLING int debugCheckflags( unsigned int debugflag );
//EXTERN CCALLING int debugdmpfmt_main(struct fmt_main *fmt_cuda_cryptsha512, const char * fmt_main_lable);
EXTERN CCALLING int debugdmpfmt_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct fmt_main *fmt_cuda_cryptsha512, const char * fmt_main_lable);

//EXTERN CCALLING int debugdmpdb_main(struct db_main *db, const char * db_main_lable);
EXTERN CCALLING int debugdmpdb_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_main *db, const char * db_main_lable);

//EXTERN CCALLING int debugdmpdb_salt(struct db_salt *dbsalt, struct db_main *db, const char * db_salt_lable);
EXTERN CCALLING int debugdmpdb_salt_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_salt *dbsalt, struct db_main *db, const char * db_salt_lable);

//EXTERN CCALLING int debugdmpdb_password(struct db_password *pw, const char * db_pw_lable);
EXTERN CCALLING int debugdmpdb_password_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_password *pw, const char * db_pw_lable);

//EXTERN CCALLING int debugdmpdb_options(struct db_options *options, const char * db_options_lable);
EXTERN CCALLING int debugdmpdb_options_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_options *optionsdb, const char * db_options_lable);

EXTERN CCALLING int debugdmplist_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct list_main *main, const char * list_main_lable);

//EXTERN CCALLING int debugdmpdb_cracked(struct db_cracked *dbcrk, const char * db_crk_lable);
EXTERN CCALLING int debugdmpdb_cracked_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct db_cracked *dbcrk, const char * db_crk_lable);

//EXTERN CCALLING int debugdmplist_main(struct list_main *main, const char * list_main_lable);
EXTERN CCALLING int debugdmplist_main_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, struct list_main *main, const char * list_main_lable);

EXTERN CCALLING void debug_dump_stuff_noeol_f(unsigned int line, const char * file, unsigned int debugflag, void *x, unsigned int size);
EXTERN CCALLING void debug_dump_stuff_f(unsigned int line, const char * file, unsigned int debugflag, void* x, unsigned int size);
EXTERN CCALLING void debug_dump_stuff_msg_f(unsigned int line, const char * file, unsigned int debugflag, const void *msg, void *x, unsigned int size);
// #ifdef DEBUG ??
EXTERN CCALLING int dyna_salt_dmp(void *_p1, void *_p2, int comp_size);
//EXTERN CCALLING void debug_dump_stuff_msg(const void *msg, void *x, unsigned int size);
EXTERN CCALLING void debug_dump_fmt( void *x, unsigned int size);
EXTERN CCALLING int debugpointertest ( void *x );
EXTERN CCALLING char * debugpointer2str ( void *x );
EXTERN CCALLING int debugpointertest ( void *x );
EXTERN CCALLING unsigned char debugSetDBLevel( int DesiredLevel );


// macros
#define debugstf(x) ( (x) ? (sDebugTrueFalse[1]) : (sDebugTrueFalse[0]) )

// conditional dump to debug device with message
#define debug_dump_stuff_msg2(d,a,b,c) if ( DBGLVLTEST > NONE ) debug_dump_stuff_msg_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump to debug device with end-of-line
#define debug_dump_stuff2(d,a,b) if ( DBGLVLTEST > NONE ) debug_dump_stuff_f(__LINE__,__FILE__,d,a,b)

// conditional dump to debug device without end-of-line
#define debug_dump_stuff_noeol2(d,a,b) if ( DBGLVLTEST > NONE ) debug_dump_stuff_noeol_f(__LINE__,__FILE__,d,a,b)

// conditional dump fmt_main structure to debug device
#define debugdmpfmt_main2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmpfmt_main_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump db_main structure to debug device
#define debugdmpdb_main2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_main_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump db.options structure to debug device
#define debugdmpdb_options2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_options_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump db.salt structure to debug device
#define debugdmpdb_salt2(d,a,b,c,e) if ( DBGLVLTEST > NONE ) debugdmpdb_salt_f(__LINE__,__FILE__,d,a,b,c,e)

// conditional dump db.passwords structure to debug device
#define debugdmpdb_password2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_password_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump db.cracked structure to debug device
#define debugdmpdb_cracked2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_cracked_f(__LINE__,__FILE__,d,a,b,c)

// conditional dump db...list structure to debug device
#define debugdmplist_main2(d,a,b,c) if ( DBGLVLTEST > NONE ) debugdmplist_main_f(__LINE__,__FILE__,d,a,b,c)

// unconditional dump to debug device with message
#define debug_dump_stuff_msg(a,b,c) if ( DBGLVLTEST > NONE ) debug_dump_stuff_msg_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump to debug device with end-of-line
#define debug_dump_stuff(a,b) if ( DBGLVLTEST > NONE ) debug_dump_stuff_f(__LINE__,__FILE__,NOHEADspecial,a,b)

// unconditional dump to debug device without end-of-line
#define debug_dump_stuff_noeol(a,b) if ( DBGLVLTEST > NONE ) debug_dump_stuff_noeol_f(__LINE__,__FILE__,NOHEADspecial,a,b)

// unconditional dump fmt_main structure to debug device
#define debugdmpfmt_main(a,b,c) if ( DBGLVLTEST > NONE ) debugdmpfmt_main_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump db_main structure to debug device
#define debugdmpdb_main(a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_main_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump db.options structure to debug device
#define debugdmpdb_options(a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_options_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump db.salt structure to debug device
#define debugdmpdb_salt(a,b,c,e) if ( DBGLVLTEST > NONE ) debugdmpdb_salt_f(__LINE__,__FILE__,99999,a,b,c,e)

// unconditional dump db.password structure to debug device
#define debugdmpdb_password(a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_password_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump db.cracked structure to debug device
#define debugdmpdb_cracked(a,b,c) if ( DBGLVLTEST > NONE ) debugdmpdb_cracked_f(__LINE__,__FILE__,99999,a,b,c)

// unconditional dump db...list structure to debug device
#define debugdmplist_main(a,b,c) if ( DBGLVLTEST > NONE ) debugdmplist_main_f(__LINE__,__FILE__,99999,a,b,c)

// define dfprintf command (conditional formatted print to debug device with line number)
#define dfprintf if ( DBGLVLTEST > NONE ) Dbgprintf

// define ddfprintf command (formatted print to debug device)
#define ddfprintf if ( DBGLVLTEST > NONE ) Dbgdmpprintf

// define dcfprintf command (conditional formatted print to debug device)
#define dcfprintf if ( DBGLVLTEST > NONE ) Dbg2dmpprintf

// define some text colors
#define DBGBOLDBLACK(x)		"\33[1;30m"#x"\33[39m"
#define DBGBOLDRED(x)		"\33[1;31m"#x"\33[39m"
#define DBGBOLDGREEN(x)		"\33[1;32m"#x"\33[39m"
#define DBGBOLDYELLOW(x)	"\33[1;33m"#x"\33[39m"
#define DBGBOLDBLUE(x)		"\33[1;34m"#x"\33[39m"
#define DBGBOLDMAGENTA(x)	"\33[1;35m"#x"\33[39m"
#define DBGBOLDCYAN(x)		"\33[1;36m"#x"\33[39m"
#define DBGBOLDWHITE(x)		"\33[1;37m"#x"\33[39m"
//#define DBGHOMECURSOR		"\33[[H"
//#define DBGCLRSCR		"\33[[2J"
#define DBGHOMECURSOR		"\33[H"
#define DBGHOMECURSORLEN	3
#define DBGCLRSCR		"\33[2J"
#define DBGCLRSCRLEN		4
#define DBGCOLOR2DEFAULT	"\33[39m\33[49m"
#define DBGCOLOR2DEFAULTLEN	10
#define DBGRESETALLATTRIBUTES	"\33[0m"
#define DBGRESETALLATTRIBUTESLEN	4

// types
	

// variables
EXTERN unsigned long long int debugheapstart INITIZERO;
EXTERN unsigned long long int debugheapend INITIZERO;
EXTERN unsigned long long int debugstackstart INITIZERO;
EXTERN unsigned long long int debugstackend INITIZERO;
EXTERN unsigned char debugVirbosity INITIZERO;
EXTERN unsigned char debugInitialVirbosity INITIZERO;
#ifdef DEBUGMAIN
EXTERN CCALLING char *sDebugTrueFalse[2] = { "False" , "True" };
#else
EXTERN CCALLING char *sDebugTrueFalse[2];
#endif

// If ColorDebug is set to true (non-zero), the debug output device is assumed to interpret ansi escape
// codes and debug output will be colorized.
// If ColorDebug is zero (default) no ansi escape sequences will be sent to the debug output device.
EXTERN int ColorDebug INITIZERO;

#define DIMDEBUGDEVICES		7
#define FILEOUTPUT 0
#define SERIALPORT 1
#define CONSOLE    2
#define TCPPORT    3
#define BITBUCKET  4
#define DEBUGWIN   5
#define RAM        6

#ifndef DEBUGMAIN
EXTERN const char *debug_devices[DIMDEBUGDEVICES];
#else
EXTERN const char *debug_devices[DIMDEBUGDEVICES] = {
	"FILEOUTPUT", \
	"SERIALPORT", \
	"CONSOLE", \
	"TCPPORT", \
	"BITBUCKET", \
	"DEBUGWIN", \
	"RAM" };
#endif  // DEBUGMAIN

#endif  // DEBUG

// define debug option indecies
#define	NONE	0
#define	NEVER	0
#define OFF	0
#define HEADUNCOND	99998
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
#define DMPFMTMAIN		16 
#define DMPDBMAIN		17
#define DBGREGISTER		18
#define DEBUGVALID		19
#define SETKEYDEBUG		20
#define GETKEYDEBUG		21
#define GETHASHDEBUG		22
#define SETSALTDEBUG		23
#define GETSALTDEBUG		24
#define FMTSELFTESTDEBUG	25
#define DYNASALTDEBUG		26
#define DEBUGDMPSTUFF		27
#define DEBUGINIT		28
#define QUIET			29
#define TRACEJOHNINIT		30
#define TRACEJOHNRUN		31
#define TRACEJOHNLOAD		32
#define TRACEJOHNLOG		33
#define TRACELOADER		34
#define TRACEDYNASALT		35
#define TRACECMPALL		36
#define TRACECMPONE		37
#define TRACECMPEXACT		38
#define TRACECUDADONE		39
#define TRACECUDAINIT		40
#define TRACECUDACRYPTALL	41
#define TRACECRYPTALL		42
#define TRACEISKEY		43
#define TRACEMISC		44
#define FMTSELFTESTDEBUGDMPSALT	45
#define TRACETESTFMTCASE	46
#define TRACEFNTDFLTRESET	47
#define TRACEFNTDFLTSPLIT	48
#define TRACECRACKER		49
#define TRACECRACKER2		50
#define TRACECRACKER3		51
#define TRACECRACKER4		52
#define TRACEBATCH		53
#define TRACESINGLE		54
#define ALLON			55
#define FMTSELFTESTDEBUGDMPFMT	56
#define BMYWAYOVERRIDE		57
#define CUDASHA512ABORT		58

#ifdef DEBUG
// define the size of the debug option arrays
#define NUMDEBUGFLAGS	60
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
	"DMPFMTMAIN", \
	"DMPDBMAIN", \
	"DBGREGISTER", \
	"DEBUGVALID", \
	"SETKEYDEBUG", \
	"GETKEYDEBUG", \
	"GETHASHDEBUG", \
	"SETSALTDEBUG", \
	"GETSALTDEBUG", \
	"FMTSELFTESTDEBUG", \
	"DYNASALTDEBUG", \
	"DEBUGDMPSTUFF", \
	"DEBUGINIT", \
	"QUIET", \
	"TRACEJOHNINIT", \
	"TRACEJOHNRUN", \
	"TRACEJOHNLOAD", \
	"TRACEJOHNLOG", \
	"TRACELOADER", \
	"TRACEDYNASALT", \
	"TRACECMPALL", \
	"TRACECMPONE", \
	"TRACECMPEXACT", \
	"TRACECUDADONE", \
	"TRACECUDAINIT", \
	"TRACECUDACRYPTALL", \
	"TRACECRYPTALL", \
	"TRACEISKEY", \
	"TRACEMISC", \
	"FMTSELFTESTDEBUGDMPSALT", \
	"TRACETESTFMTCASE", \
	"TRACEFNTDFLTRESET", \
	"TRACEFNTDFLTSPLIT", \
	"TRACECRACKER", \
	"TRACECRACKER2", \
	"TRACECRACKER3", \
	"TRACECRACKER4", \
	"TRACEBATCH", \
	"TRACESINGLE", \
	"ALLON", \
	"FMTSELFTESTDEBUGDMPFMT", \
	"BMYWAYOVERRIDE", \
	"CUDASHA512ABORT", \
	""};

#endif
// define the debug option status flags
EXTERN unsigned char bdebug_flag_set[NUMDEBUGFLAGS] INITSZERO;

#else   //    else !DEBUG
// create dummy debug_dump_stuff_msg2 command for non-debug compiles
#define debug_dump_stuff_msg2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff2 command for non-debug compiles
#define debug_dump_stuff2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol2 command for non-debug compiles
#define debug_dump_stuff_noeol2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_msg command for non-debug compiles
#define debug_dump_stuff_msg if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff command for non-debug compiles
#define debug_dump_stuff if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debug_dump_stuff_noeol if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpfmt_main2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_main2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_options2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_salt2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_password2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_cracked2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmplist_main2 if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpfmt_main if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_main if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_options if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_salt if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_password if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmpdb_cracked if (0) ((int (*)(const char *, ...)) 0)

// create dummy debug_dump_stuff_noeol command for non-debug compiles
#define debugdmplist_main if (0) ((int (*)(const char *, ...)) 0)

// create dummy dfprintf command for non-debug compiles
#define dfprintf if (0) ((int (*)(int, ...)) 0)

// create dummy ddfprintf command for non-debug compiles
#define ddfprintf if (0) ((int (*)(const char *, ...)) 0)

// create dummy dcfprintf command for non-debug compiles
#define dcfprintf if (0) ((int (*)(const char *, ...)) 0)

// create dummy debugstf() and jtrunwind() macros for non-debug compiles
#define debugstf(x) (0)
#define jtrunwind(x) (0)


// create dummy color macros
#define DBGBOLDBLACK(x)		#x
#define DBGBOLDRED(x)		#x
#define DBGBOLDGREEN(x)		#x
#define DBGBOLDYELLOW(x)	#x
#define DBGBOLDBLUE(x)		#x
#define DBGBOLDMAGENTA(x)	#x
#define DBGBOLDCYAN(x)		#x
#define DBGBOLDWHITE(x)		#x
#define DBGHOMECURSOR		""
#define DBGHOMECURSORLEN	0
#define DBGCLRSCR		""
#define DBGCLRSCRLEN		0
#define DBGCOLOR2DEFAULT	""
#define DBGCOLOR2DEFAULTLEN	0
#define DBGRESETALLATTRIBUTES	""
#define DBGRESETALLATTRIBUTESLEN	0

#endif  //    fi DEBUG
#endif  //    fi _JOHN_DEBUG_H
