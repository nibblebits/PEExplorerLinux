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


    printf("Pointer to PE start=%x\n", (int)file.dos_header.e_lfanew);


    return 0;
}