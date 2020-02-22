#include "pefile.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>

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

    if (*((uint32_t *)sig) != 0x4550)
    {
        status = PE_STATUS_INVALID_PE_FILE;
        goto out;
    }

    // Let's load the PE file header
    res = fread(&file->pe_header, sizeof(file->pe_header), 1, f);
    if (res != 1)
    {
        status = PE_STATUS_READ_FAILURE;
        goto out;
    }

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
    if (!status)
        goto out;

out:
    return status;
}