#include <stdio.h>
#include <memory.h>
#include "pefile.h"

void virus(int a, int b)
{
    a = a + b + 1;
}

void a()
{

}

int main(int argc, char** argv)
{

    if (argc < 2)
    {
        printf("Expecting a filename of the .EXE file to manage\n");
        return -1;
    }


    struct pefile file;
    pefile_init(&file);
    if(pefile_load(argv[1], "rw+", &file) != PE_STATUS_OK)
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


    // Let's create a new section
    int _size = (int)((void*)&a - (void*)virus);
    char buf[_size];
    memcpy(buf, virus, _size);

    struct pefile_section* section = pefile_section_create(&file, ".cool", buf, sizeof(buf), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (section)
    {
        file.optional_header.standard_fields.address_of_entry_point = section->header->virtual_address;
        pefile_save_header(&file);
    }


    printf("Pointer to PE start=%x\n", (int)file.dos_header.e_lfanew);


    return 0;
}