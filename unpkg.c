// Copyright (C) 2013       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/gpl-2.0.txt

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "sha2.h"

#define PS4_PKG_MAGIC					0x544E437F // .CNT

enum PS4_PKG_ENTRY_TYPES {
	PS4_PKG_ENTRY_TYPE_DIGEST_TABLE = 0x0001,
	PS4_PKG_ENTRY_TYPE_0x800        = 0x0010,
	PS4_PKG_ENTRY_TYPE_0x200        = 0x0020,
	PS4_PKG_ENTRY_TYPE_0x180        = 0x0080,
	PS4_PKG_ENTRY_TYPE_META_TABLE   = 0x0100,
	PS4_PKG_ENTRY_TYPE_NAME_TABLE   = 0x0200,
	PS4_PKG_ENTRY_TYPE_LICENSE      = 0x0400,
	PS4_PKG_ENTRY_TYPE_FILE1        = 0x1000,
	PS4_PKG_ENTRY_TYPE_FILE2        = 0x1200
};


#ifdef _WIN32
	#define OS_SEPARATOR "\\"
#else
	#define OS_SEPARATOR "/"
#endif

// CNT/PKG structures.
struct cnt_pkg_main_header {
	uint32_t magic;
	uint32_t type;
	uint32_t unk_0x08;
	uint32_t unk_0x0C;
	uint16_t unk1_entries_num;
	uint16_t table_entries_num;
	uint16_t system_entries_num;
	uint16_t unk2_entries_num;
	uint32_t file_table_offset;
	uint32_t main_entries_data_size;
	uint32_t unk_0x20;
	uint32_t body_offset;
	uint32_t unk_0x28;
	uint32_t body_size;
	uint8_t  unk_0x30[0x10];
	uint8_t  content_id[0x30];
	uint32_t unk_0x70;
	uint32_t unk_0x74;
	uint32_t unk_0x78;
	uint32_t unk_0x7C;
	uint32_t date;
	uint32_t time;
	uint32_t unk_0x88;
	uint32_t unk_0x8C;
	uint8_t  unk_0x90[0x70];
	uint8_t  main_entries1_digest[0x20];
	uint8_t  main_entries2_digest[0x20];
	uint8_t  digest_table_digest[0x20];
	uint8_t  body_digest[0x20];
} __attribute__((packed));

struct cnt_pkg_content_header {
	uint32_t unk_0x400;
	uint32_t unk_0x404;
	uint32_t unk_0x408;
	uint32_t unk_0x40C;
	uint32_t unk_0x410;
	uint32_t content_offset;
	uint32_t unk_0x418;
	uint32_t content_size;
	uint32_t unk_0x420;
	uint32_t unk_0x424;
	uint32_t unk_0x428;
	uint32_t unk_0x42C;
	uint32_t unk_0x430;
	uint32_t unk_0x434;
	uint32_t unk_0x438;
	uint32_t unk_0x43C;
	uint8_t  content_digest[0x20];
	uint8_t  content_one_block_digest[0x20];
} __attribute__((packed));

struct cnt_pkg_table_entry {
	uint32_t type;
	uint32_t unk1;
	uint32_t flags1;
	uint32_t flags2;
	uint32_t offset;
	uint32_t size;
	uint32_t unk2;
	uint32_t unk3;
} __attribute__((packed));

// Internal structure.
struct file_entry {
	int offset;
	int size;
	char *name;
};

// Helper functions.
static inline uint16_t bswap_16(uint16_t val)
{
	return ((val & (uint16_t)0x00ffU) << 8)
		| ((val & (uint16_t)0xff00U) >> 8);
}

static inline uint32_t bswap_32(uint32_t val)
{
	return ((val & (uint32_t)0x000000ffUL) << 24)
		| ((val & (uint32_t)0x0000ff00UL) <<  8)
		| ((val & (uint32_t)0x00ff0000UL) >>  8)
		| ((val & (uint32_t)0xff000000UL) >> 24);
}

static inline uint64_t bswap_64(uint64_t val)
{
	return ((val & (uint64_t)0x00000000000000ffULL) << 56)
		| ((val & (uint64_t)0x000000000000ff00ULL) << 40)
		| ((val & (uint64_t)0x0000000000ff0000ULL) << 24)
		| ((val & (uint64_t)0x00000000ff000000ULL) <<  8)
		| ((val & (uint64_t)0x000000ff00000000ULL) >>  8)
		| ((val & (uint64_t)0x0000ff0000000000ULL) >> 24)
		| ((val & (uint64_t)0x00ff000000000000ULL) >> 40)
		| ((val & (uint64_t)0xff00000000000000ULL) >> 56);
}

char *read_string(FILE* f)
{
	char *string = malloc(sizeof(char) * 256);
    int c;
	int length = 0;
    if(!string) return string;
    while((c = fgetc(f)) != '\00')
	{
        string[length++] = c;
    }
	string[length++] = '\0';

    return realloc(string, sizeof(char) * length);
}

char *build_path(const char *str, char c, const char *r)
{
    int count = 0;
    const char *tmp;
    for (tmp = str; *tmp; tmp++) {
        count += (*tmp == c);
	}

    int rlen = strlen(r);
    char *res = malloc(strlen(str) + (rlen - 1) * count + 1);
    char *ptr = res;
    for (tmp = str; *tmp; tmp++) {
        if (*tmp == c) {
		    mkdir(res, S_IRWXU);
            memcpy(ptr, r, rlen);
            ptr += rlen;
        } else {
            *ptr++ = *tmp;
        }
    }
    *ptr = 0;
    return res;
}

typedef struct {
	uint32_t type;
	char *name;
} pkg_entry_value;

char *get_entry_name_by_type(uint32_t type)
{
	pkg_entry_value entries [] = {
		{ PS4_PKG_ENTRY_TYPE_DIGEST_TABLE, "digest_table.bin"          },
		{ PS4_PKG_ENTRY_TYPE_0x800,        "unknown_entry_0x800.bin"   },
		{ PS4_PKG_ENTRY_TYPE_0x200,        "unknown_entry_0x200.bin"   },
		{ PS4_PKG_ENTRY_TYPE_0x180,        "unknown_entry_0x180.bin"   },
		{ PS4_PKG_ENTRY_TYPE_META_TABLE,   "meta_table.bin"            },
		{ PS4_PKG_ENTRY_TYPE_NAME_TABLE,   "name_table.bin"            },
		{ 0x0400,                          "license.dat"               },
		{ 0x0401,                          "license.info"              },
		{ 0x1000,                          "param.sfo"                 },
		{ 0x1001,                          "playgo-chunk.dat"          },
		{ 0x1002,                          "playgo-chunk.sha"          },
		{ 0x1003,                          "playgo-manifest.xml"       },
		{ 0x1004,                          "pronunciation.xml"         },
		{ 0x1005,                          "pronunciation.sig"         },
		{ 0x1006,                          "pic1.png"                  },
		{ 0x1008,                          "app/playgo-chunk.dat"      },
		{ 0x1200,                          "icon0.png"                 },
		{ 0x1220,                          "pic0.png"                  },
		{ 0x1240,                          "snd0.at9"                  },
		{ 0x1260,                          "changeinfo/changeinfo.xml" }
	};
	char *entry_name = NULL;
	size_t i;
	for (i = 0; i < sizeof entries / sizeof entries[0]; i++) {
		if (type == entries[i].type) {
			entry_name = entries[i].name;
			break;
		}
	}

	return entry_name;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: unpkg [PKG FILE]\n");
		return 0;
	}

	FILE *in = NULL;
	FILE *out = NULL;
	struct cnt_pkg_main_header m_header;
	struct cnt_pkg_content_header c_header;
	memset(&m_header, 0, sizeof(struct cnt_pkg_main_header));
	memset(&c_header, 0, sizeof(struct cnt_pkg_content_header));

	if ((in = fopen(argv[1], "rb")) == NULL) {
		printf("File not found!\n");
		return 0;
	}

	// Read in the main CNT header (size seems to be 0x180 with 4 hashes included).
	fseek(in, 0, SEEK_SET);
	fread(&m_header, 1,  0x180, in);

	if (m_header.magic != PS4_PKG_MAGIC) {
		printf("Invalid PS4 PKG file!\n");
		return 0;
	}

	printf("PS4 PKG header:\n");
	printf("- PKG magic: 0x%X\n", bswap_32(m_header.magic));
	printf("- PKG type: 0x%X\n", bswap_32(m_header.type));
	printf("- PKG table entries: %d\n", bswap_16(m_header.table_entries_num));
	printf("- PKG system entries: %d\n", bswap_16(m_header.system_entries_num));
	printf("- PKG table offset: 0x%X\n", bswap_32(m_header.file_table_offset));
	printf("\n\n");

	// Seek to offset 0x400 and read content associated header (size seems to be 0x80 with 2 hashes included).
	fseek(in, 0x400, SEEK_SET);
	fread(&c_header, 1,  0x80, in);

	printf("PS4 PKG content header:\n");
	printf("- PKG content offset: 0x%X\n", bswap_32(c_header.content_offset));
	printf("- PKG content size: 0x%X\n", bswap_32(c_header.content_size));
	printf("\n\n");

	// Locate the entry table and list each type of section inside the PKG/CNT file.
	fseek(in, bswap_32(m_header.file_table_offset), SEEK_SET);

	printf("PS4 PKG table entries:\n");
	struct cnt_pkg_table_entry entries[m_header.table_entries_num];
	int i;
	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		fread(&entries[i], 1,  0x20, in);
		printf("Entry #%d\n", i);
		printf("- PKG table entry type: 0x%X\n", bswap_32(entries[i].type));
		printf("- PKG table entry offset: 0x%X\n", bswap_32(entries[i].offset));
		printf("- PKG table entry size: 0x%X\n", bswap_32(entries[i].size));
		printf("\n");
	}
	printf("\n");

	// Vars for file name listing.
	struct file_entry entry_files[bswap_16(m_header.table_entries_num)];
	char *file_name_list[256];
	char *unknown_file_name;
	int file_name_index = 0;
	int unknown_file_count = 0;
	int file_count = 0;

	// Vars for entry mapping.
	int entry_size;
	int entry_offset;
	unsigned char *entry_digests;

	// Vars for calculating SHA-256 hashes.
	unsigned char *main_entries_data = NULL;
	unsigned char *main_entries_sub_data = NULL;
	unsigned char *digest_table_data = NULL;
	unsigned char *body_data = NULL;
	unsigned char *content_one_block_data = NULL;
	unsigned char *content_data = NULL;

	int main_entries_data_size = 0;
	int main_entries_sub_data_size = 0;
	int digest_table_data_size = 0;
	int body_data_size = 0;

	unsigned char computed_main_entries_digest[0x20];
	unsigned char computed_main_entries_sub_digest[0x20];
	unsigned char computed_digest_table_digest[0x20];
	unsigned char computed_body_digest[0x20];
	unsigned char computed_content_one_block_digest[0x20];
	unsigned char computed_content_digest[0x20];

	int block_size = 0x10000;
	int num_blocks = (c_header.content_size > 0) ? 1 + ((c_header.content_size - 1) / block_size) : 0;

	// Var for file writing.
	unsigned char *entry_file_data;

	// Search through the data entries and locate the name table entry.
	// This section should keep relevant strings for internal files inside the PKG/CNT file.
	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		if (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_NAME_TABLE) {
			printf("Found name table entry. Extracting file names:\n");
			fseek(in, bswap_32(entries[i].offset) + 1, SEEK_SET);
			while ((file_name_list[file_name_index] = read_string(in))[0] != '\0') {
				printf("%s\n", file_name_list[file_name_index]);
				file_name_index++;
			}
			printf("\n");
		}
	}

	// Search through the data entries and locate file entries.
	// These entries need to be mapped with the names collected from the name table.
	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		// Use a predefined list for most file names.
		entry_files[i].name = get_entry_name_by_type(bswap_32(entries[i].type));
		entry_files[i].offset = bswap_32(entries[i].offset);
		entry_files[i].size = bswap_32(entries[i].size);

		if (((bswap_32(entries[i].type) & PS4_PKG_ENTRY_TYPE_FILE1) == PS4_PKG_ENTRY_TYPE_FILE1)
			|| (((bswap_32(entries[i].type) & PS4_PKG_ENTRY_TYPE_FILE2) == PS4_PKG_ENTRY_TYPE_FILE2))) {
			// If a file was found and it's name is not on the predefined list, try to map it with
		    // a name from the name table.
			if (entry_files[i].name == NULL) {
				entry_files[i].name = file_name_list[file_count];
			}
			file_count++;
		} else {
			// If everything failed, give a custom unknown tag to the file.
			if (entry_files[i].name == NULL) {
				unknown_file_name = (char *)malloc(256);
				sprintf(unknown_file_name, "unknown_file_%d.bin", ++unknown_file_count);
				entry_files[i].name = unknown_file_name;
			}
		}
	}
	printf("Successfully mapped %d files.\n\n", file_count);

	// Search through the data entries and generate SHA-256 hashes for checking with the hash table.
	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		// Calculate hash for the digest table.
		if ((bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_DIGEST_TABLE)) {
			entry_size = bswap_32(entries[i].size);
			entry_offset = bswap_32(entries[i].offset);
			entry_digests = (unsigned char *)realloc(NULL, entry_size);

			fseek(in, entry_offset, SEEK_SET);
			fread(entry_digests, 1,  entry_size, in);

			digest_table_data_size += entry_size;
			digest_table_data = (unsigned char *)realloc(NULL, digest_table_data_size);
			*digest_table_data += *entry_digests;
		}
	}
	sha2(digest_table_data, digest_table_data_size, computed_digest_table_digest, 0);

	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		// Calculate first hash for the main entries.
		if ((bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_DIGEST_TABLE)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x800)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x200)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x180)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_META_TABLE))
		{
			entry_size = bswap_32(entries[i].size);
			entry_offset = bswap_32(entries[i].offset);
			entry_digests = (unsigned char *)realloc(NULL, entry_size);

			fseek(in, entry_offset, SEEK_SET);
			fread(entry_digests, 1,  entry_size, in);

			main_entries_data_size += entry_size;
			main_entries_data = (unsigned char *)realloc(NULL, main_entries_data_size);
			*main_entries_data += *entry_digests;
		}
	}
	sha2(main_entries_data, main_entries_data_size, computed_main_entries_digest, 0);

	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		// Calculate second hash for the main entries.
		if ((bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x800)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x200)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_0x180)
			|| (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_META_TABLE))
		{
			if ((bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_META_TABLE)) {
				entry_size = bswap_16(m_header.system_entries_num) * 0x20;
			} else {
				entry_size = bswap_32(entries[i].size);
			}
			entry_offset = bswap_32(entries[i].offset);
			entry_digests = (unsigned char *)realloc(NULL, entry_size);

			fseek(in, entry_offset, SEEK_SET);
			fread(entry_digests, 1,  entry_size, in);

			main_entries_sub_data_size += entry_size;
			main_entries_sub_data = (unsigned char *)realloc(NULL, main_entries_sub_data_size);
			*main_entries_sub_data += *entry_digests;
		}
	}
	sha2(main_entries_sub_data, main_entries_sub_data_size, computed_main_entries_sub_digest, 0);

	// Calculate hash for file body.
	body_data_size = m_header.body_size;
	body_data = (unsigned char *)malloc(body_data_size);
	fseek(in, m_header.body_offset, SEEK_SET);
	fread(body_data, 1,  body_data_size, in);
	sha2(body_data, body_data_size, computed_body_digest, 0);

	// Calculate hash for one block of the content section.
	content_one_block_data = (unsigned char *)malloc(block_size);
	fseek(in, c_header.content_offset, SEEK_SET);
	fread(content_one_block_data, 1,  block_size, in);
	sha2(content_one_block_data, block_size, computed_content_one_block_digest, 0);

	// Calculate hash for the entire content section.
	content_data = (unsigned char *)malloc(block_size);
	fseek(in, c_header.content_offset, SEEK_SET);

	int bytes_left = c_header.content_size;
	int current_size;
	int b;
	sha2_context ctx;
	sha2_starts(&ctx, 0);
	for (b = 0; b < num_blocks; b++) {
		current_size = (bytes_left > block_size) ? block_size : bytes_left;
		fread(content_data, 1,  current_size, in);
		sha2_update(&ctx, content_data, current_size);
		bytes_left -= block_size;
	}
	sha2_finish(&ctx, computed_content_digest);

	int s;
	printf("Calculated SHA-256 hashes:\n");
	printf("Main entries 1:\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_main_entries_digest[s]);
	printf("\n");

	printf("Main entries 2:\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_main_entries_sub_digest[s]);
	printf("\n");

	printf("Digest table:\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_digest_table_digest[s]);
	printf("\n");

	printf("Body:\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_body_digest[s]);
	printf("\n");

	printf("Content (1 block):\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_content_one_block_digest[s]);
	printf("\n");

	printf("Content:\n");
	for(s = 0; s < 0x20; s++) printf("%X", computed_content_digest[s]);
	printf("\n\n");

	// Set up the output directory for file writing.
	char dest_path[256];
	char pkg_name[256];
	memset(pkg_name, 0, 256);
	memcpy(pkg_name, argv[1], 0x13);
	mkdir(pkg_name, S_IRWXU);

	// Search through the entries for mapped file data and output it.
	printf("Dumping internal PKG files:\n");
	for (i = 0; i < bswap_16(m_header.table_entries_num); i++) {
		entry_file_data = (unsigned char *)realloc(NULL, entry_files[i].size);

		fseek(in, entry_files[i].offset, SEEK_SET);
		fread(entry_file_data, 1,  entry_files[i].size, in);

		sprintf(dest_path, "%s%s%s", pkg_name, OS_SEPARATOR, entry_files[i].name);

		char *path = build_path(dest_path, '/', OS_SEPARATOR);
		printf("%s\n", path);

		if ((out = fopen(path, "wb")) == NULL ) {
			printf("Can't open file for writing!\n");
			return 0;
		}

		fwrite(entry_file_data, 1, entry_files[i].size, out);
	}

	// Clean up.
	fclose(in);
	fclose(out);

	printf("Finished!\n");

	return 0;
}
