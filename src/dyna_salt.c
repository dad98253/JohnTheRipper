/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2014. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2014 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 * This is a dynamic salt structure.  In a hash that has salts which
 * vary in size. To make a local salt structure usable by dyna_salt
 * code in John, simply place an instance of a dyna_salt structure as
 * the FIRST member of your salt structure, and then properly fill in
 * the members of that structure.  This will make your structure 'look'
 * just like a dyna_salt_john_core structure. That is the structure
 * that john core code uses, so john core can access your structure,
 * without having to know its full internal structure. Then define the
 * rest of the salt structure to be the 'real' salt structure you need
 * for the runtime of your hash.  In your format structure, set the salt_size
 * to be sizeof(dyna_salt*)  and set the FMT_DYNA_SALT format flag. See
 * zip format for an example of how to properly use dyna_salt's.
 */

#include <stddef.h>
#include "formats.h"
#include "memory.h"
#include "dyna_salt.h"
#include "loader.h"
#include "md5.h"
#include "memdbg.h"
#include "debug.h"

static struct fmt_main *format;
#ifdef DYNA_SALT_DEBUG
static int salt_count;
#endif

struct fmt_main *dyna_salt_init(struct fmt_main *_format) {
	struct fmt_main *p = format;

	dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_init: called... does nothing... returns pointer to format\n");

	format=_format;
	return p;
}

#ifdef DYNA_SALT_DEBUG
void dyna_salt_remove_fp(void *p, char *fname, int line)
#else
void dyna_salt_remove_fp(void *p)
#endif
{

	dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_remove_fp (called from %s): get_salt() for dynamic format -> %s\n",jtrunwind(1),debugstf(p && (!format || (format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT)));

	if (p && (!format || /* get_salt() for dynamic format called from within valid() */
	          (format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT)) {
		dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);

		dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_remove_fp (called from %s): (p1 && p1->dyna_salt.salt_alloc_needs_free == 1) -> %s\n",jtrunwind(1),debugstf(p1 && p1->dyna_salt.salt_alloc_needs_free == 1));

		if (p1 && p1->dyna_salt.salt_alloc_needs_free == 1) {
#ifdef DYNA_SALT_DEBUG
#if defined (MEMDBG_ON)
			const char *msg;
			printf ("-- Freeing a salt    #%d  from: %s line %d  mdbg_alloc-cnt=%u  mdbg_allocfile=%s mdbg_allocline=%u\n",
			         --salt_count, fname, line, MEMDBG_get_cnt(p1,&msg),MEMDBG_get_file(p1,&msg),MEMDBG_get_line(p1,&msg));
#else
			printf ("-- Freeing a salt    #%d  from: %s line %d\n", --salt_count, fname, line);

			dfprintf(__LINE__,__FILE__,DYNASALTDEBUG,"-- Freeing a salt    #%d  from: %s line %d\n", salt_count, fname, line);

#endif
#endif
			MEM_FREE(p1);
		}
	}
}

#ifdef DYNA_SALT_DEBUG
void dyna_salt_created_fp(void *p, char *fname, int line) {

	dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_created_fp (%s): create salt in dynamic format -> %s\n",jtrunwind(0),debugstf((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT));

	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
#if defined (MEMDBG_ON)
		const char *msg;
		dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);

		dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_remove_fp (%s): (p1 && p1->dyna_salt.salt_alloc_needs_free == 1) -> %s\n",jtrunwind(0),debugstf(p1 && p1->dyna_salt.salt_alloc_needs_free == 1));

		if (p1 && p1->dyna_salt.salt_alloc_needs_free == 1)
			printf ("++ Allocating a salt #%d  from: %s line %d  mdbg_alloc-cnt=%u  mdbg_allocfile=%s mdbg_allocline=%u\n",
			         ++salt_count, fname, line, MEMDBG_get_cnt(p1,&msg),MEMDBG_get_file(p1,&msg),MEMDBG_get_line(p1,&msg));
#else
		printf ("++ Allocating a salt #%d  from: %s line %d\n", ++salt_count, fname, line);
#endif
	}
}
#endif

int dyna_salt_cmp(void *_p1, void *_p2, int comp_size) {
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		dyna_salt_john_core *p1 = *((dyna_salt_john_core**)_p1);
		dyna_salt_john_core *p2 = *((dyna_salt_john_core**)_p2);
#ifdef DYNA_SALT_DEBUG
		debug_dump_stuff_msg2(DEBUGDYNASALT,"dyna_salt_cmp\np1", &((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset], p1->dyna_salt.salt_cmp_size>48?48:p1->dyna_salt.salt_cmp_size);
		debug_dump_stuff_msg2(DEBUGDYNASALT,"p2", &((unsigned char*)p2)[p2->dyna_salt.salt_cmp_offset], p2->dyna_salt.salt_cmp_size>48?48:p2->dyna_salt.salt_cmp_size);
#endif
		if (p1->dyna_salt.salt_cmp_offset == p2->dyna_salt.salt_cmp_offset &&
		    p1->dyna_salt.salt_cmp_size == p2->dyna_salt.salt_cmp_size &&
		    !memcmp( &((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset],
		             &((unsigned char*)p2)[p2->dyna_salt.salt_cmp_offset],
		             p1->dyna_salt.salt_cmp_size))
			return 0;
		return 1;
	}
#ifdef DYNA_SALT_DEBUG
	debug_dump_stuff_msg2(DEBUGDYNASALT,"salt_cmp\np1", _p1, comp_size>48?48:comp_size);
	debug_dump_stuff_msg2(DEBUGDYNASALT,"p2", _p2, comp_size>48?48:comp_size);
#endif
	// non-dyna salt compare.
	return memcmp(_p1, _p2, comp_size);
}

#ifdef DEBUG
int dyna_salt_dmp(void *_p1, void *_p2, int comp_size) {
	dyna_salt_john_core *p1;
	dyna_salt_john_core *p2;
	intptr_t uP1, uP2, uEnd, uArg;
 	extern char etext, edata, end; /* The symbols must have some type,
                                          or "gcc -Wall" complains */
	static int firstcall = 1;

	uP1 = (intptr_t)_p1;
	uP2 = (intptr_t)_p2;
	uEnd = (intptr_t)&end;
	uArg = (intptr_t)(&comp_size);
	debug_read_proc_file(0);
	if ( firstcall ) {
           firstcall = 0;
           dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"First address past:\n");
           dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    program text (etext)         %016p\n", &etext);
           dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    initialized data (edata)     %016p\n", &edata);
           dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    uninitialized data (end)     %016p\n", &end);
	   dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    _p1, _p2, uP1, uP2           %016p, %016p, 0x%016lx 0x%016lx\n",_p1,_p2,uP1,uP2);
	   dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    uEnd                       0x%016llx\n",uEnd);
	   dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    debugheapstart             0x%016llx\n",debugheapstart);
	   dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"    debugheapend               0x%016llx\n",debugheapend);
	   dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"    debugstackstart            0x%016llx\n",debugstackstart);
	   dfprintf(__LINE__,__FILE__,DEBUGPROCFILE,"    uArg                       0x%016lx\n",uArg);
	}
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		p1 = *((dyna_salt_john_core**)_p1);
		p2 = *((dyna_salt_john_core**)_p2);
		dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"dyna_salt_dmp called from %s: comp_size = %i , _p1 = %016p, _p2 = %016p :\n",
			jtrunwind(1),comp_size,_p1,_p2);
		if ( ( uP1 != 0 && uP1 < debugheapend ) || uP1 > debugstackstart ) {
			dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"p1.salt_cmp_size = %i, p1.salt_alloc_needs_free = %i, p1.salt_cmp_offset = %i\n",
				p1->dyna_salt.salt_cmp_size,p1->dyna_salt.salt_alloc_needs_free,p1->dyna_salt.salt_cmp_offset);
			debug_dump_stuff_msg("p1", &((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset], p1->dyna_salt.salt_cmp_size>48?48:p1->dyna_salt.salt_cmp_size);
		} else {
			dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"dyna_salt_dmp : dump fail... uP1 = 0x%016lx , debugheapend = 0x%016lx, debugstackstart = 0x%016llx :\n",
				uP1,debugheapend,debugstackstart);
		}
		if ( ( uP2 != 0 && uP2 < debugheapend ) || uP1 > debugstackstart ) {
			dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"p2.salt_cmp_size = %i, p2.salt_alloc_needs_free = %i, p2.salt_cmp_offset = %i\n",
				p2->dyna_salt.salt_cmp_size,p2->dyna_salt.salt_alloc_needs_free,p2->dyna_salt.salt_cmp_offset);
			debug_dump_stuff_msg("p2", &((unsigned char*)p2)[p2->dyna_salt.salt_cmp_offset], p2->dyna_salt.salt_cmp_size>48?48:p2->dyna_salt.salt_cmp_size);
		} else {
			dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"dyna_salt_dmp : dump fail... uP2 = 0x%016lx , debugheapend = 0x%016lx, debugstackstart = 0x%016llx :\n",
				uP2,debugheapend,debugstackstart);
		}
	} else {
		dfprintf(__LINE__,__FILE__,TRACEDYNASALT,"salt_dmp called from %s: comp_size = %i , _p1 = %016p, _p2 = %016p :\n",jtrunwind(1),comp_size,_p1,_p2);
		if ( ( uP1 != 0 && uP1 < debugheapend ) || uP1 > debugstackstart ) {
			debug_dump_stuff_msg("p1", _p1, comp_size>48?48:comp_size);
		} else {
			dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"salt_dmp : dump fail... uP1 = 0x%016lx , debugheapend = 0x%016lx, debugstackstart = 0x%016llx :\n",
				uP1,debugheapend,debugstackstart);
		}
		if ( ( uP2 != 0 && uP2 < debugheapend ) || uP1 > debugstackstart ) {
			debug_dump_stuff_msg("p2", _p2, comp_size>48?48:comp_size);
		} else {
			dfprintf(__LINE__,__FILE__,DEBUGSALTDUMP,"salt_dmp : dump fail... uP2 = 0x%016lx , debugheapend = 0x%016lx, debugstackstart = 0x%016llx :\n",
				uP2,debugheapend,debugstackstart);
		}
	}

	if ( uP1 == 0 || uP2 == 0 || uP1 > debugheapend || uP2 > debugheapend ) return 0;
	return 1;
}
#endif

void dyna_salt_md5(struct db_salt *p, int comp_size) {
	MD5_CTX ctx;

	MD5_Init(&ctx);
	if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
		dyna_salt_john_core *ds = *((dyna_salt_john_core**)p->salt);
		MD5_Update(&ctx, &((unsigned char*)ds)[ds->dyna_salt.salt_cmp_offset],
		           ds->dyna_salt.salt_cmp_size);
	} else
		MD5_Update(&ctx, (unsigned char*)p->salt, comp_size);
	MD5_Final((unsigned char *)p->salt_md5, &ctx);
}

void dyna_salt_smash(void *p, char c) {
	dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);
	memset(&((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset], 0xAF, p1->dyna_salt.salt_cmp_size);
}
int dyna_salt_smash_check(void *p, unsigned char c) {
	dyna_salt_john_core *p1 = *((dyna_salt_john_core**)p);
	return (((unsigned char*)p1)[p1->dyna_salt.salt_cmp_offset+p1->dyna_salt.salt_cmp_size-1] == c);
}
