#include <stdio.h>
#include "pefile.h"
int main(int argc, char** argv)
{

    if (argc < 2)
    {
        printf("Expecting a filename of the .EXE file to manage\n");
        return -1;
    }


    struct pefile file;
    pefile_init(&file);
    if(pefile_load(argv[1], "r", &file) != PE_STATUS_OK)
    {
        printf("Problem reading PE file is it valid?\n");
        return -1;
    }

    uint16_t characteristics = file.pe_header.characteristics;
    const char* msg = NULL;
    while((msg = pefile_characteristic(&characteristics)) != NULL)
    {
        printf("%s\n", msg);
    }

    struct pefile_section* section = pefile_section_open(&file, "CODE");
    if (!section)
    {
        printf("Failed to open code section\n");
        return -1;
    }

    // Read the first 20 bytes
    char buf[20];
    if(pefile_section_read(section, buf, sizeof(buf)) != PE_STATUS_OK)
    {
        printf("Failed to read 20 bytes from section\n");
        return -1;
    }
    pefile_section_close(section);

    printf("Pointer to PE start=%x\n", (int)file.dos_header.e_lfanew);


    return 0;
}