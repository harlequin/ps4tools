// Copyright (C) 2013       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/gpl-2.0.txt

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PS4_PUP_PACK_MAGIC        0x32424C53 // SLB2
#define PS4_PUP_PACK_HEADER_SIZE  0x200

// Main PUP packed header (size == 0x20):
// 0x00: 53 4C 42 32 -> SLB2 
// 0x04: 01 00 00 00 -> Version?
// 0x08: 00 00 00 00 -> Unknown
// 0x0C: 02 00 00 00 -> Number of PUP files in this pack
// 0x10: 03 9F 09 00 -> Total number of blocks (512 bytes)
// 0x14: 00 00 00 00 -> Unknown
// 0x18: 00 00 00 00 -> Unknown
// 0x1C: 00 00 00 00 -> Unknown
struct pup_pack_header {
	uint32_t magic;
	uint32_t version;
	uint32_t unk1;
	uint32_t pup_file_num;
	uint32_t pup_total_block_num;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
	struct pup_entry *pup_entry_list;
} __attribute__((packed));

// PUP file entry (size == 0x30):
// 0x00: 01 00 00 00 -> Offset (in blocks, so 1 is the first block of 512 bytes after the header)
// 0x04: 00 76 AE 0D -> File size
// 0x08: 00 00 00 00 -> Unknown
// 0x0C: 00 00 00 00 -> Unknown
// 0x10: 50 53 34 55 -> File name (e.g.: PS4UPDATE1.PUP) (0x20 bytes)
// 0x14: 50 44 41 54 
// 0x18: 45 31 2E 50 
// 0x1C: 55 50 00 00 
// 0x20: 00 00 00 00 
// 0x24: 00 00 00 00 
// 0x28: 00 00 00 00 
// 0x2C: 00 00 00 00
struct pup_entry {
	uint32_t block_offset;
	uint32_t file_size;
	uint32_t unk1;
	uint32_t unk2;
	uint8_t  file_name[32];
} __attribute__((packed));

int main (int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: pupunpack [PS4UPDATE.PUP]\n");
		return 0;
	}
	
	// Open file and set up the header struct.
	FILE *in;
	FILE *out;
	struct pup_pack_header header;
	memset(&header, 0, sizeof(struct pup_pack_header));
	
	if ((in = fopen(argv[1], "rb")) == NULL ) {
		printf("File not found!\n");
		return 0;
	}
	
	// Read in the main pack header.
	fseek(in, 0, SEEK_SET);
	fread(&header, 1,  0x20, in);
	
	if (header.magic != PS4_PUP_PACK_MAGIC) {
		printf("Invalid PS4 PUP file!\n");
		return 0;
	}
	
	printf("PS4 PUP pack header:\n");
	printf("- PUP pack magic: 0x%X\n", header.magic);
	printf("- PUP pack version: %i\n", header.version);
	printf("- PUP files in this pack: %i\n", header.pup_file_num);
	printf("- Total number of blocks: %i\n", header.pup_total_block_num);
	printf("\n");
	
	// Read in all the PUP entries.
	int i;
	header.pup_entry_list = malloc(header.pup_file_num * sizeof(struct pup_entry));

	for (i = 0; i < header.pup_file_num; ++i) {
		fread(&header.pup_entry_list[i], 1, 0x30, in);
		printf("PUP file entry %i:\n", i);
		printf("- Block offset: 0x%X\n", header.pup_entry_list[i].block_offset);
		printf("- PUP file size: %i\n", header.pup_entry_list[i].file_size);
		printf("- PUP file name: %s\n", header.pup_entry_list[i].file_name);
		printf("\n");
	}

	// Create a large enough buffer and start copying the data.
	int buffer_size = PS4_PUP_PACK_HEADER_SIZE * 4;
	int pup_offset = PS4_PUP_PACK_HEADER_SIZE;
	uint8_t buffer[buffer_size];
	
	int ii;
	for (ii = 0; ii < header.pup_file_num; ++ii) {
		fseek(in, pup_offset, SEEK_SET);
		out = fopen(header.pup_entry_list[ii].file_name, "wb");	

		printf("Dumping PUP file %s from offset 0x%X with size %i\n", header.pup_entry_list[ii].file_name, pup_offset, header.pup_entry_list[ii].file_size);
		
		int fsize = header.pup_entry_list[ii].file_size;
		pup_offset += (fsize + 511) & ~511; // 512 bytes alignment.
		
		while (fsize > 0) {
			if (fsize > buffer_size) {
				fread(buffer, 1, buffer_size, in);
				fwrite(buffer, 1, buffer_size, out);
				fsize -= buffer_size;
			} else {
				fread(buffer, 1, fsize, in);
				fwrite(buffer, 1, fsize, out);
				fsize = 0;	
			}
		}
	
		fclose(out);
	}	

	fclose(in);

	printf("Finished!\n");
	
	return 0;
}