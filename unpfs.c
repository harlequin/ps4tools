// Copyright (C) 2016       harlequin
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/gpl-2.0.txt

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
    u64 version;
    u64 magic;
    u32 id[2];
    char fmode;
    char clean;
    char ronly;
    char rsv;
    u16 mode;
    u16 unk1;
    u32 blocksz;
    u32 nbackup;
    u64 nblock;
    u64 ndinode;
    u64 ndblock;
    u64 ndinodeblock;
    u64 superroot_ino;	
} pfs_header_t;

typedef struct {
    u16 mode;
    u16 nlink;
    u32 flags;
    u64 size;
    char unk1[56];
    u32 uid;
    u32 gid;
    u64 unk2[2];
    u32 blocks;
    int db[12];
    u32 ib[5];
} di_d32;

typedef struct {
    u32 ino;
    u32 type;
    u32 namelen;
    u32 entsize;
    //char name[namelen+1];
} dirent;

static u8 *pfs = NULL;
pfs_header_t *header;
static di_d32 inodes[0x20];

static void parse_directory( int ino, di_d32 *parent, u8 *parent_name ) {
	u32 z;
	
	for ( z = 0; z < 12; z++ ) {		
		if ( inodes[ino].db[z] <= 0) { continue; }
		
		printf("=====================================\n");
		printf("inode ino=%x size=%lld mode=%x db=%x\n", ino, inodes[ino].size, inodes[ino].mode, inodes[ino].db[z]);
	
		u64 pos = header->blocksz * inodes[ino].db[z];
			
		while ( pos < header->blocksz * (inodes[ino].db[z] + 1)) {
				
			dirent *ent;
			ent = malloc(sizeof(dirent));					
			memcpy( ent, pfs + pos, sizeof(dirent));
			if (ent->type == 0) {
				break;
			}						
				
			printf("==> pos %x ino=%d \n", pos, ent->ino);
				
			char *name;
			name = malloc(ent->namelen + 1);
			name[ent->namelen] = '\0';
					
			memcpy( name, pfs + pos + 0x10, ent->namelen );
				
			char fname[256];
			if ( parent_name != NULL ) {
				sprintf(fname, "%s/%s"	, parent_name, name);
			} else {
				sprintf(fname, "%s", name);
			}
				
			if ( ent->type == 2) {
				printf("len: %x name: '%.*s' type: %x index:%d\n",ent->namelen,ent->namelen, name, ent->type, ent->ino);						
				printf("Dumping from pos=%x destination=%s\n", inodes[ent->ino].db[z] * header->blocksz, fname);					
				memcpy_to_file( fname, pfs + inodes[ent->ino].db[z] * header->blocksz, inodes[ent->ino].size );							
			} else if (ent->type == 3) {
				printf("len: %x name: '%.*s' type: %x\n",ent->namelen,ent->namelen, name, ent->type);
				printf("scan directory ent->ino %x - '%s'\n", ent->ino, name);
				MKDIR(fname, 0777);
				parse_directory( ent->ino, &inodes[ino], fname);
			}
			
			pos += ent->entsize;
		}						
	}
}

int main(int argc, char *argv[]) {		
	u32 i;
	u32 j;	
	
	if (argc != 2 && argc != 3)
		fail("usage: unpfs filename [target]");
	
	pfs = mmap_file(argv[1]);
	
	if ( argv[2] != NULL )
		MKDIR(argv[2], 0777);
		
	header = malloc(sizeof(pfs_header_t));
	memcpy( header, pfs, sizeof(pfs_header_t) );
	
	for(i = 0; i < header->ndinodeblock; i++) {		
		printf("stream pos %x\n", header->blocksz + header->blocksz * i );
		for ( j = 0; j < header->ndinode; j++ ){
			memcpy ( &inodes[j], pfs + header->blocksz + (sizeof(di_d32) * j), sizeof(di_d32));			
			printf("inode ino=%x pos=%x mode=%x size=%llu uid=%x gid=%x\n",j, header->blocksz + (sizeof(di_d32) * j), inodes[j].mode, inodes[j].size, inodes[j].uid, inodes[j].gid);
		}
		printf("=========================\n");		
		parse_directory( header->superroot_ino , NULL, argv[2]);
	}
	
	return 0;
}