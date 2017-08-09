/*  CrazyVoid Generate PS4 IDX File
 *  - 07/24/2017
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
 
#include "tools.h"
 
u8 magicPreset[0x9] = { 0x72, 0x69, 0x64, 0x78, 0x01, 0x00, 0x00, 0x00, 0x01 };
u8 padding1Preset[0x4] = { 0x00, 0x00, 0x00, 0x00 };
u8 unknownPreset[0x16] = { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
u8 padding2Preset[0x16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
 
u8 outputFile[0x50];
 
int generateIDX(char *CONTENT_ID, char *ENTITLEMENT_LABEL)
{
    int ret;
    if(strlen(CONTENT_ID) == 19)
    {
        if(strlen(ENTITLEMENT_LABEL) == 16)
        {
            char outputFilename[30] = "fake";
            strcat(outputFilename, CONTENT_ID);
            strcat(outputFilename, ".idx");
            printf("Output : %s\n\n", outputFilename);
 
            memcpy(outputFile, magicPreset, 9);
            memcpy(outputFile+9, CONTENT_ID, 19);
            memcpy(outputFile+28, padding1Preset, 4);
            memcpy(outputFile+32, ENTITLEMENT_LABEL, 16);
            memcpy(outputFile+48, unknownPreset, 16);
            memcpy(outputFile+64, padding2Preset, 16);
 
            FILE *fp;
            fp = fopen(outputFilename, "w+");
            fwrite(outputFile, sizeof(outputFile), 1, fp);
            fclose(fp);
            ret = 0;
        }
        else
        {
            printf("[ERROR] Invalid length of ENTITLEMENT LABLE\nFailed to create IDX\n\n");
            ret = 1;
        }
    }
    else
    {
        printf("[ERROR] Invalid length of CONTENT ID\nFailed to create IDX\n\n");
        ret = 2;
    }
 
    return ret;
}
 
void help_Output()
{
    printf("====PS4 IDX Generator - CrazyVoid======\n");
    #ifdef WIN32
    printf("genidx.exe CONTENT_ID ENTITLEMENT_LABEL\n\n");
    #else
    printf("./genidx CONTENT_ID ENTITLEMENT_LABEL\n\n");
    #endif
    printf("[ERROR] INCORRECT AMOUNT OF ARGUMENTS\n\n");
}
 
int main(int argc, char *argv[])
{
    int ret;
 
 
    if (argc != 3)
    {
        help_Output();
        ret = 3;
    }
    else
    {
        // Dont change this line, stealing others work is not nice :)
        // If you add code, feel free to add your name.
        printf("[CrazyVoid] IDX Generator v0.1\n");
        ret = generateIDX(argv[1], argv[2]);
    }
 
    return ret;
}
