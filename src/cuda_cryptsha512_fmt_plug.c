/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_cryptsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_cryptsha512);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_cryptsha512.h"
#include "cuda_common.h"
// these MUST be defined prior to loading cryptsha512_valid.h
#define BINARY_SIZE			64
#define SALT_LENGTH			16
#define CIPHERTEXT_LENGTH		86
#define __CRYPTSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "cryptsha512_common.h"
#include "memdbg.h"
#include "debug.h"

#define FORMAT_LABEL		"sha512crypt-cuda"
#define FORMAT_NAME		"crypt(3) $6$"

#define ALGORITHM_NAME		"SHA512 CUDA (inefficient, please use sha512crypt-opencl instead)"

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define MD5_DIGEST_LENGTH 	16

#define BINARY_ALIGN		8
#define SALT_ALIGN			sizeof(uint32_t)

#define SALT_SIZE		(3+7+9+16)

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static crypt_sha512_password *inbuffer;		/** plaintext ciphertexts **/
static crypt_sha512_hash *outbuffer;		/** calculated hashes **/

void sha512_crypt_gpu(crypt_sha512_password * inbuffer,
	crypt_sha512_hash *outbuffer, crypt_sha512_salt *host_salt, int count);

static char currentsalt[64];
static crypt_sha512_salt _salt;

static void done(void)
{

 dfprintf(__LINE__,__FILE__,TRACECUDADONE,"done: called..., called from %s\n",jtrunwind(1));

 MEM_FREE(inbuffer);
 MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
  //Allocate memory for hashes and passwords
  inbuffer = (crypt_sha512_password*)mem_calloc(MAX_KEYS_PER_CRYPT,
                                                sizeof(crypt_sha512_password));
  outbuffer=(crypt_sha512_hash*)mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(crypt_sha512_hash));
  check_mem_allocation(inbuffer,outbuffer);
#ifdef DEBUG
  dfprintf(__LINE__,__FILE__,TRACECUDAINIT,"init: initializing cuda..., MAX_KEYS_PER_CRYPT = %i, sizeof(crypt_sha512_password) = %i, called from %s\n",MAX_KEYS_PER_CRYPT,sizeof(crypt_sha512_password),jtrunwind(1));
  dfprintf(__LINE__,__FILE__,TRACECUDAINIT,"init: maximum usable size of inbuffer = %i\n",malloc_usable_size(inbuffer));
  dfprintf(__LINE__,__FILE__,TRACECUDAINIT,"init: sizeof(crypt_sha512_hash) = %i, maximum usable size of outbuffer = %i\n",sizeof(crypt_sha512_hash),malloc_usable_size(outbuffer));
#endif 
  //Initialize CUDA
  cuda_init();
}

static void *get_salt(char *ciphertext)
{
	int end = 0;
	int i;
	int len;
	static unsigned char ret[50];
	len = strlen(ciphertext);

        dfprintf(__LINE__,__FILE__,GETSALTDEBUG,"get_salt: parsing ciphertext to find salt..., ciphertext = %s, len = %i, called from %s\n", ciphertext,len,jtrunwind(1));

	memset(ret, 0, sizeof(ret));
	for (i = len - 1; i >= 0; i--) {
		if (ciphertext[i] == '$') {
			end = i;
			break;
		}
	}
#ifdef DEBUG
	if ( end > 50 ) {
		fprintf(stderr,"bad get_salt call, end = %i\n",end);
		exit(EXIT_FAILURE);
	}
#endif
	for (i = 0; i < end; i++)
		ret[i] = ciphertext[i];
	ret[end] = 0;
	return (void *) ret;
}

static void set_salt(void *salt)
{
	unsigned char *s = salt;
	int len = strlen(salt);
	unsigned char offset = 0;
	_salt.rounds = ROUNDS_DEFAULT;
	memcpy(currentsalt,s,len+1);

        dfprintf(__LINE__,__FILE__,SETSALTDEBUG,"set_salt: saving salt...(%s) , len+1 = %i (MUST be <= 64), called from %s\n",salt,len+1,jtrunwind(1));

	if (strncmp((char *) FORMAT_TAG, (char *) currentsalt, FORMAT_TAG_LEN) == 0) {
		offset += FORMAT_TAG_LEN;
	} else {
	        dfprintf(__LINE__,__FILE__,SETSALTDEBUG,"set_salt: ////// Warning : FORMAT_TAG (%s) missing, FORMAT_TAG_LEN = %i\n",FORMAT_TAG,FORMAT_TAG_LEN);
	}

	if (strncmp((char *) currentsalt + offset, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX)-1) == 0) {
		const char *num = currentsalt + offset + sizeof(ROUNDS_PREFIX)-1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	} else {
	        dfprintf(__LINE__,__FILE__,SETSALTDEBUG,"set_salt: ////// Warning : ROUNDS_PREFIX (%s) missing\n",ROUNDS_PREFIX);
	}
	memcpy(_salt.salt, currentsalt + offset, 16);
	_salt.saltlen = strlen(_salt.salt);
#ifdef DEBUG
 	dfprintf(__LINE__,__FILE__,SETSALTDEBUG,"set_salt: (%s) saved in _salt, _salt.saltlen = %i\n",_salt.salt,_salt.saltlen);

	if (_salt.saltlen > 16 ) {
       		dfprintf(__LINE__,__FILE__,TRACE,"set_salt: ////// Error : _salt.saltlen > 16 (%i)\n",_salt.saltlen);
		exit(EXIT_FAILURE);
	}
#endif
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
#ifdef DEBUG
	if ( index > (MAX_KEYS_PER_CRYPT-1) ) {
	        dfprintf(__LINE__,__FILE__,TRACE,"set_key: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		exit(EXIT_FAILURE);
	}
	if ( len > 16 ) {
	        dfprintf(__LINE__,__FILE__,TRACE,"set_key: ////// Error : len (%i) > 16\n",len);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	inbuffer[index].length = len;
	memcpy(inbuffer[index].v, key, len);

        dfprintf(__LINE__,__FILE__,SETKEYDEBUG,"set_key: saving key # %i...(%s), len = %i, called from %s\n",index,key,len,jtrunwind(1));

}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
//	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	memcpy(ret, inbuffer[index].v, inbuffer[index].length);  // changed by jck
	ret[inbuffer[index].length] = '\0';

        dfprintf(__LINE__,__FILE__,GETKEYDEBUG,"get_key: fetching key # %i...(%s), called from %s\n",index,ret,jtrunwind(1));

	return ret;
}


static void gpu_crypt_all(int count)
{

        dfprintf(__LINE__,__FILE__,TRACECUDACRYPTALL,"gpu_crypt_all: called with count = %i... called from %s\n",count,jtrunwind(1));

	sha512_crypt_gpu(inbuffer, outbuffer, &_salt, count);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

        dfprintf(__LINE__,__FILE__,TRACECRYPTALL,"crypt_all: called with count = %i...  called from %s\n",count,jtrunwind(1));

	gpu_crypt_all(count);
	return count;
}

static int get_hash_0(int index)
{

        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_0: fetching hash # %i... called from %s\n",index,jtrunwind(1));
#ifdef DEBUG
	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,TRACE,"get_hash_0: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_1: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_1: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_2: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_2: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_3: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_3: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_4: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_4: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_5: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_5: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_5;
}
static int get_hash_6(int index)
{
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_6: fetching hash # %i...\n",index);

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,GETHASHDEBUG,"get_hash_6: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	return outbuffer[index].v[0] & PH_MASK_6;
}


static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint64_t b = ((uint64_t *) binary)[0];
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,TRACECMPALL,"cmp_all: called from %s, count = %i\n",jtrunwind(1),count);

	if ( count > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,TRACECMPALL,"cmp_all: ////// Error : count (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",count,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint64_t *t = (uint64_t *) binary;
#ifdef DEBUG
        dfprintf(__LINE__,__FILE__,TRACECMPONE,"cmp_one: called from %s\n",jtrunwind(1));

	if ( index > (MAX_KEYS_PER_CRYPT - 1) ) {
	        dfprintf(__LINE__,__FILE__,TRACECMPONE,"cmp_one: ////// Error : index (%i) > MAX_KEYS_PER_CRYPT-1 (%i)\n",index,MAX_KEYS_PER_CRYPT-1);
		if ( bdebug_flag_set[CUDASHA512ABORT] ) exit(EXIT_FAILURE);
	}
#endif
	for (i = 0; i < 8; i++) {
		if (t[i] != outbuffer[index].v[i])
			return 0;
	}
	return 1;
}

static int cmp_exact(char *source, int index)
{

        dfprintf(__LINE__,__FILE__,TRACECMPEXACT,"cmp_exact: (does nothing...) called from %s\n",jtrunwind(1));

	return 1;
}

/*
// iteration count as tunable cost parameter
static unsigned int iteration_count(void *salt)
{
	crypt_sha512_salt *sha512crypt_salt;

	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
*/

struct fmt_main fmt_cuda_cryptsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			NULL, //"iteration count"
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,	//	1
		done,	//	2
		fmt_default_reset,	//	3
		fmt_default_prepare,	//	4
		valid,	//	5
		fmt_default_split,	//	6
		get_binary,	//	7
		get_salt,	//	8
		{
			NULL, //iteration_count,	//	9 (tunable_cost_value)
		},
		fmt_default_source,	//	10
		{	//	11
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,	//	12
		NULL,	//	13(salt_compare)
		set_salt,	//	14
		set_key,	//	15
		get_key,	//	16
		fmt_default_clear_keys,	//	17
		crypt_all,	//	18
		{	//	19
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,	//	20
		cmp_one,	//	21
		cmp_exact	//	22
	}
};

#endif /* plugin stanza */

#endif /* HAVE_CUDA */
