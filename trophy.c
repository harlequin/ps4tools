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
#include <wincrypt.h>
#else
#include <sys/mman.h>
#endif

#ifdef WIN32
#define MKDIR(x,y) mkdir(x)
#else
#define MKDIR(x,y) mkdir(x,y)
#endif

#include "types.h"
#include "tools.h"

typedef struct {
 	unsigned int magic; // 
 	unsigned int version;
 	unsigned long file_size; // size of full trp file
 	unsigned int entry_num; // num entries
 	unsigned int entry_size; // size of entry
 	unsigned int dev_flag; // 1: dev
 	unsigned char digest[20]; //sha1 hash
 	unsigned int key_index;
 	unsigned char padding[44];
 } trp_header;
 
 typedef struct {
 	signed char entry_name[32];
 	unsigned long entry_pos;
 	unsigned long entry_len;
 	unsigned int flag; //3 on some, 0 on others, could be flags or an enum to determine if encrypted or not?
 	unsigned char padding[12];
 } trp_entry;


static u8 *trophy = NULL;
u8 key[0x10]= {0};
u8 iv[0x10] = {0};
u8 ckey[0x10];
u8 civ[0x10];
trp_header *header;
u8 np_comm_id[0x10];


u8 brutforce_npcommid (u8 *ptr, u64 len) {
	u32 i;
	u8 *out;
	u8 *str;

	// printf("[!] Bruteforce attack started ... ");
		
	for ( i = 0; i < 99999; i++ ) {					
		memset(np_comm_id, 0, 0x10);
		sprintf(np_comm_id, "%s%05d_00", "NPWR", i);
		aes128cbc_enc( key, iv, np_comm_id, 0x10, ckey);
		
		memcpy(civ, ptr, 0x10);
						
		out = malloc(len - 0x10);
		aes128cbc(ckey, civ, ptr + 0x10,  len - 0x10, out);
					
		str = malloc(0x04);
		memcpy(str, out, 0x04);
					
		if ( !strcmp(str, "<!--") ) {
			printf("Key found [%s]!\n", np_comm_id);						
			return 0;
		}
	}
	printf("Failed!\n");
	return 1;
}



int main(int argc, char *argv[]) {		
	u32 i;
	u32 j;	
	u32 z;
	u64 pos;	

	
	trp_entry *entry;
		
	if (argc != 2 && argc != 3)
		fail("usage: trophy filename [target]");
	
	trophy = mmap_file(argv[1]);
	
	if ( argv[2] != NULL ) {
		MKDIR(argv[2], 0777);
		if (chdir(argv[2]) != 0)
			fail("chdir(%s)", argv[2]);		
	}
	
	header = malloc(sizeof(trp_header));
	memcpy( header, trophy, sizeof(trp_header) );
	
	printf("[+] Tophy Magic 0x%X\n", header->magic);
	printf("[+] Tophy Version 0x%x\n", header->version);
	header->file_size = be64(trophy + 0x08);
	printf("[+] Tophy File Size 0%X\n", header->file_size);
	
	header->entry_num = be32(trophy + 0x10);
	
	printf("[+] Tophy Number of Entries %d\n", header->entry_num);
	printf("[+] Tophy Size of Entry: 0x%x\n", header->entry_size);
	printf("[+] Tophy Dev Flag: 0x%x\n", header->dev_flag);
	printf("[+] Tophy SHA-1 Hash: 0x%x\n", header->digest);
	
	
	if ( header->dev_flag == 0x40000000 ) {
		if (key_get_simple("trp-key-retail", key, 0x10) < 0)
			fail("failed to load the ps4 trp retail key.");
	} else {
		if (key_get_simple("trp-key-debug", key, 0x10) < 0)
			fail("failed to load the ps4 trp debug key.");
	}
		
	for(i = 0; i < header->entry_num; i++) {
		
		entry = malloc(sizeof(trp_entry));
		if(!entry) {
			printf("Error in malloc\n");
		}
		
		pos = 0x60 + (i * 0x40);

		memcpy( entry->entry_name, trophy + pos, 0x20);
		entry->entry_pos = be64( trophy + pos + 0x20 );
		entry->entry_len = be64( trophy + pos + 0x20 + 0x08 );			
		entry->flag = be32( trophy + pos + 0x20 + 0x08 + 0x08);	
		
		printf("[*] Entry Name: %.*s Pos: 0x%X Len: 0x%X Flag: 0x%X\n", 32, entry->entry_name, entry->entry_pos, entry->entry_len, entry->flag);
				
		if ( entry->flag == 3 ) {
			//encrypted files detected
			if ( np_comm_id == NULL ) {
				if ( brutforce_npcommid(trophy + entry->entry_pos, entry->entry_len) == 1) {
					fail("failed to bruteforce.");
				}				
			} 
			
			memcpy(civ, trophy + entry->entry_pos, 0x10);			
			aes128cbc(ckey, civ, trophy + entry->entry_pos + 0x10,  entry->entry_len - 0x10, trophy + entry->entry_pos + 0x10);
			memcpy_to_file( entry->entry_name, trophy + entry->entry_pos + 0x10, entry->entry_len - 0x10 );	
					
		} else {
			memcpy_to_file( entry->entry_name, trophy + entry->entry_pos, entry->entry_len );	
		}		
	}
	
	return 0;
}
