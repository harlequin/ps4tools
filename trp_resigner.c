/*
 * Copyright (C) harlequin
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <zlib.h>
#include <dirent.h>
#include <assert.h>
#include <stdint.h>

#ifdef WIN32
#include "mingw_mmap.h"
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include "types.h"
#include "tools.h"

u8 np[0x10];
u8 np2[0x10];
u8 iv[0x10] = {0};
u8 new_civ[0x10] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
u8 *ptr;
u8 key[0x10]= {0};
u8 key2[0x10]= {0};
u8 org_key[0x10];
u8 new_key[0x10];	

typedef struct {
 	u8 entry_name[32];
 	u64 entry_pos;
 	u64 entry_len;
 	u32 flag; //3 on some, 0 on others, could be flags or an enum to determine if encrypted or not?
 	u8 padding[12];
 } trp_entry;

int main(int argc, char *argv[]) {
	u32 num;
	u64 pos;	
	u64 sz;
	u32 i;
	
	if (argc != 4)
		fail("usage: trp_resigner trophy.trp np_comm_id debug_trophy.trp");
			
	ptr = mmap_file(argv[1]);
	
	sz = be64(ptr + 0x08);
	num = be32(ptr + 0x10);	
		
	if (key_get_simple("trp-key-retail", key, 0x10) < 0)
		fail("failed to load the ps4 trp retail key.");
	
	if (key_get_simple("trp-key-debug", key2, 0x10) < 0)
		fail("failed to load the ps4 trp debug key.");
	
	//org key
	memset(np, 0x00, 0x10);
	memcpy(np, argv[2], 12);	
	aes128cbc_enc(key, iv, np, 0x10, org_key);
	
	//new key
	memset(np2, 0x00, 0x10);
	memcpy(np2, "AAAA00000_00", 12);		
	aes128cbc_enc(key2, iv, np2, 0x10, new_key);
			
	for(i = 0; i < num; i++) {	
		pos = 0x60 + (i * 0x40);

		trp_entry *e;
		e = malloc(0x40);
		
		e->entry_pos = be64( ptr + pos + 0x20 );
		e->entry_len = be64( ptr + pos + 0x20 + 0x08 );			
		e->flag = be32( ptr + pos + 0x20 + 0x08 + 0x08);	
						
		if ( e->flag == 0x03 ) {			
					
			u8 civ[0x10] = {0};
			memcpy(civ, ptr + e->entry_pos, 0x10);
			
			//decrypt
			aes128cbc(org_key, civ, ptr + e->entry_pos + 0x10,  e->entry_len - 0x10, ptr + e->entry_pos + 0x10);
			
			//size of signature is 0x140, set it to x's
			memset(ptr + e->entry_pos + 0x2D, 'x', 0x140);
			
			//print to screen to check validity
			//printf("%s\n", ptr + e->entry_pos + 0x10);
			
			//encrypt with new key np			
			aes128cbc_enc(new_key, new_civ, ptr + e->entry_pos + 0x10,  e->entry_len - 0x10, ptr + e->entry_pos + 0x10);

			//copy new_civ to old civ
			memcpy(ptr + e->entry_pos, new_civ , 0x10);
			
			//set new flag
			e->flag = 0x02;
			wbe32( ptr + pos + 0x20 + 0x08 + 0x08, e->flag);
		}
	}
	
	//set header flag to development (not needed)
	//wbe32(ptr + 0x18, 0x00000001);
	
	//calculate sha1 - set to zero, calc, store
	memset(ptr + 0x1C, 0, 0x14);
	//set flag to 0 (debug)
	memset(ptr + 0x31, '0', 1);
	sha1(ptr, sz, ptr + 0x1C);	
	
	memcpy_to_file(argv[3], ptr , sz );
	
	return 0;
}