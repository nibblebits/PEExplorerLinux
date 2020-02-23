#include "pefile.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

const char *pefile_characteristic(uint16_t *c)
{
    const char *result = NULL;

    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_FILE_EXECUTEABLE, "PE File is executable", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_FILE_IS_DLL, "PE File is an DLL(Dynamic Link Library)", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_FILE_IS_SYSTEM, "PE File is a system file", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_RELOCATION_INFO_STRIPPED, "PE File has had its relocation information stripped", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_LINE_NUMBERS_STRIPPED, "PE File has had its line numbers stripped", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_LOCAL_SYMBOLS_STRIPPED, "PE File has had its local symbols stripped", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_AGGRESSIVE_TRIM, "PE File has had an aggressive trim", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_CAN_HANDLE_2GB_PLUS, "PE File can handle 2GB+", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_BYTES_RESERVED_LOW, "PE File bytes reserved low", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_32_BIT_WORD_MACHINE, "PE File is 32 bit word machine", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_COPY_RUN_FILE_IF_EXTERNAL_MEDIA, "PE File should copy the file and then run it if the media is external", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_COPY_RUN_ON_SWAP_IF_NET_FILE, "PE File run on the swap if this is a network file", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_UP_MACHINE_ONLY, "PE File should run on an \"UP\" machine only", out)
    PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, PE_CHARACTERISTIC_BYTES_OF_MACHINE_WORD_RESERVED_HIGH, "PE File bytes of the machine are reserved high", out)

out:
    return result;
}

void pefile_init(struct pefile *file)
{
    memset(file, 0, sizeof(struct pefile));
}

static bool pefile_valid_optional_magic(uint16_t magic)
{
    return magic == PE_FILE_NORMAL_EXECUTABLE || magic == PE_FILE_ROM_IMAGE || magic == PE_FILE_PE32_PLUS;
}

static PE_STATUS pefile_load_optional_header_standard_fields(FILE *f, struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    if (*to_read < sizeof(file->optional_header.standard_fields))
    {
        status = PE_STATUS_NO_OPTIONAL_HEADER;
        goto out;
    }

    // Read in the standard fields
    FREAD_OR_FAIL(&file->optional_header.standard_fields, sizeof(file->optional_header.standard_fields), f, status, out);

    *to_read -= sizeof(file->optional_header.standard_fields);

    if (!pefile_valid_optional_magic(file->optional_header.standard_fields.magic))
    {
        status = PE_STATUS_OPTIONAL_HEADER_BAD_MAGIC;
        goto out;
    }

out:
    return status;
}

static PE_STATUS pefile_load_optional_header_image_fields(FILE *f, struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    if (*to_read < sizeof(file->optional_header.image_fields))
    {
        // No image fields available
        goto out;
    }

    // Read the image fields
    FREAD_OR_FAIL(&file->optional_header.image_fields, sizeof(file->optional_header.image_fields), f, status, out);

out:
    return status;
}

static PE_STATUS pefile_load_optional_header_data_directories(FILE *f, struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    uint32_t total = file->optional_header.image_fields.number_of_rva_and_sizes;
    struct pefile_pe_data_directory *data_directories = (struct pefile_pe_data_directory *)calloc(sizeof(struct pefile_pe_data_directory), total);
    for (int i = 0; i < total; i++)
    {
        FREAD_OR_FAIL(&data_directories[i], sizeof(struct pefile_pe_data_directory), f, status, out);
    }

    file->optional_header.data_directories = data_directories;
out:
    return status;
}

static PE_STATUS pefile_load_optional_header(FILE *f, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    size_t to_read = file->pe_header.size_of_optional_header;
    status = pefile_load_optional_header_standard_fields(f, file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

    if (file->optional_header.standard_fields.magic != PE_FILE_PE32_PLUS)
    {
        // Data field must be present
        FREAD_OR_FAIL(&file->optional_header.base_of_data, sizeof(file->optional_header.base_of_data), f, status, out);
    }

    if (to_read < sizeof(file->optional_header.image_fields))
    {
        // No image fields available
        goto out;
    }

    // Load the image fields
    status = pefile_load_optional_header_image_fields(f, file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

    // Load the data directories
    status = pefile_load_optional_header_data_directories(f, file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

out:
    return status;
}

static PE_STATUS pefile_load_section_headers(FILE *f, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    struct pefile_section_header *headers = (struct pefile_section_header *)calloc(sizeof(struct pefile_section_header), file->pe_header.number_of_sections);
    for (int i = 0; i < file->pe_header.number_of_sections; i++)
    {
        FREAD_OR_FAIL(&headers[i], sizeof(struct pefile_section_header), f, status, out);
    }

    file->section_headers = headers;
out:
    return status;
}

struct pefile_section_header* pefile_find_section(struct pefile* file, const char* name)
{
    char _name[PE_SECTION_NAME_SIZE];
    memset(_name, 0, sizeof(_name));
    memcpy(_name, name, strnlen(name, sizeof(_name)));
    struct pefile_section_header* ptr = NULL;

    for (int i = 0; i < file->pe_header.number_of_sections; i++)
    {
        if (memcmp(_name, file->section_headers[i].name, sizeof(_name)) == 0)
        {
            ptr = &file->section_headers[i];
        }
    }

    return ptr;
}

static PE_STATUS pefile_load_dos_header(FILE *f, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = fread(&file->dos_header, sizeof(file->dos_header), 1, f);
    if (res != 1)
    {
        status = PE_STATUS_DOS_HEADER_READ_FAILURE;
        goto out;
    }

    if (file->dos_header.e_magic != 0x5A4D)
    {
        status = PE_STATUS_INVALID_PE_FILE;
        goto out;
    }

out:
    return status;
}


static PE_STATUS pefile_load_pe_header(FILE *f, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    char sig[PE_SIGNATURE_SIZE];
    int res = -1;
    fseek(f, file->dos_header.e_lfanew, SEEK_SET);
    res = fread(sig, PE_SIGNATURE_SIZE, 1, f);
    if (res != 1)
    {
        status = PE_STATUS_READ_FAILURE;
        goto out;
    }

    if (*((uint32_t *)sig) != PE_SIGNATURE)
    {
        status = PE_STATUS_INVALID_PE_FILE;
        goto out;
    }

    // Let's load the PE file header
    FREAD_OR_FAIL(&file->pe_header, sizeof(file->pe_header), f, status, out);

out:
    return status;
}

PE_STATUS pefile_load(const char *filename, const char *mode, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    FILE *f = fopen(filename, mode);
    status = pefile_load_dos_header(f, file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_pe_header(f, file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_optional_header(f, file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_section_headers(f, file);
    if (status != PE_STATUS_OK)
        goto out;

out:
    return status;
}