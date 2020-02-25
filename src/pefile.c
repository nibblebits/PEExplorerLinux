#include "pefile.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
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

static PE_STATUS pefile_load_optional_header_standard_fields(struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    if (*to_read < sizeof(file->optional_header.standard_fields))
    {
        status = PE_STATUS_NO_OPTIONAL_HEADER;
        goto out;
    }

    // Read in the standard fields
    FREAD_OR_FAIL(&file->optional_header.standard_fields, sizeof(file->optional_header.standard_fields), file->fd, status, out);

    *to_read -= sizeof(file->optional_header.standard_fields);

    if (!pefile_valid_optional_magic(file->optional_header.standard_fields.magic))
    {
        status = PE_STATUS_OPTIONAL_HEADER_BAD_MAGIC;
        goto out;
    }

out:
    return status;
}

static PE_STATUS pefile_load_optional_header_image_fields(struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    if (*to_read < sizeof(file->optional_header.image_fields))
    {
        // No image fields available
        goto out;
    }

    // Read the image fields
    FREAD_OR_FAIL(&file->optional_header.image_fields, sizeof(file->optional_header.image_fields), file->fd, status, out);

out:
    return status;
}

static PE_STATUS pefile_load_optional_header_data_directories(struct pefile *file, size_t *to_read)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    uint32_t total = file->optional_header.image_fields.number_of_rva_and_sizes;
    struct pefile_pe_data_directory *data_directories = (struct pefile_pe_data_directory *)calloc(sizeof(struct pefile_pe_data_directory), total);
    for (int i = 0; i < total; i++)
    {
        FREAD_OR_FAIL(&data_directories[i], sizeof(struct pefile_pe_data_directory), file->fd, status, out);
    }

    file->optional_header.data_directories = data_directories;
out:
    return status;
}

static PE_STATUS pefile_load_optional_header(struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    size_t to_read = file->pe_header.size_of_optional_header;
    status = pefile_load_optional_header_standard_fields(file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

    if (file->optional_header.standard_fields.magic != PE_FILE_PE32_PLUS)
    {
        // Data field must be present
        FREAD_OR_FAIL(&file->optional_header.base_of_data, sizeof(file->optional_header.base_of_data), file->fd, status, out);
        to_read -= sizeof(file->optional_header.base_of_data);
    }

    if (to_read < sizeof(file->optional_header.image_fields))
    {
        // No image fields available
        goto out;
    }

    // Load the image fields
    status = pefile_load_optional_header_image_fields(file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

    // Load the data directories
    status = pefile_load_optional_header_data_directories(file, &to_read);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

out:
    return status;
}

static PE_STATUS pefile_load_section_headers(struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;

    file->offset_to_section_headers = ftell(file->fd);
    
    struct pefile_section_header *headers = (struct pefile_section_header *)calloc(sizeof(struct pefile_section_header), file->pe_header.number_of_sections);
    for (int i = 0; i < file->pe_header.number_of_sections; i++)
    {
        FREAD_OR_FAIL(&headers[i], sizeof(struct pefile_section_header), file->fd, status, out);
    }

    file->section_headers = headers;
out:
    return status;
}

struct pefile_section_header *pefile_section_header_last(struct pefile *file)
{
    if (file->pe_header.number_of_sections == 0)
        return NULL;

    return &file->section_headers[file->pe_header.number_of_sections - 1];
}

struct pefile_section_header *pefile_find_section(struct pefile *file, const char *name)
{
    char _name[PE_SECTION_NAME_SIZE];
    memset(_name, 0, sizeof(_name));
    memcpy(_name, name, strnlen(name, sizeof(_name)));
    struct pefile_section_header *ptr = NULL;

    for (int i = 0; i < file->pe_header.number_of_sections; i++)
    {
        if (memcmp(_name, file->section_headers[i].name, sizeof(_name)) == 0)
        {
            ptr = &file->section_headers[i];
        }
    }

    return ptr;
}

struct pefile_section *pefile_section_open(struct pefile *file, const char *name)
{
    struct pefile_section *section = NULL;
    struct pefile_section_header *header = pefile_find_section(file, name);
    if (header)
    {
        section = pefile_section_open_by_header(file, header);
    }

    return section;
}

uint32_t pefile_section_size(struct pefile_section *section)
{
    return section->header->raw_size;
}

uint32_t pefile_section_tell(struct pefile_section *section)
{
    return section->pos;
}

struct pefile_section *pefile_section_open_by_header(struct pefile *file, struct pefile_section_header *header)
{
    struct pefile_section *section = (struct pefile_section *)malloc(sizeof(struct pefile_section));
    section->file = file;
    section->pos = 0;
    section->header = header;
    return section;
}

void pefile_section_close(struct pefile_section *section)
{
    free(section);
}

PE_STATUS pefile_section_read(struct pefile_section *section, void *out, size_t amount)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    uint32_t abs_pos = section->header->raw_address + section->pos;
    uint64_t end_pos = section->header->raw_address + section->header->raw_size;
    if (abs_pos >= end_pos)
    {
        status = PE_STATUS_READ_FAILURE;
        goto out;
    }

    res = fseek(section->file->fd, abs_pos, SEEK_SET);
    if (res)
    {
        status = PE_STATUS_READ_FAILURE;
        goto out;
    }

    FREAD_OR_FAIL(out, amount, section->file->fd, status, out);
    section->pos += amount;

out:
    return status;
}

PE_STATUS pefile_section_write(struct pefile_section *section, const void *in, size_t amount)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = -1;
    uint32_t abs_pos = section->header->raw_address + section->pos;
    uint64_t end_pos = section->header->raw_address + section->header->raw_size;

    // Extending of a section is not implemented in this version
    if (abs_pos >= end_pos)
    {
        status = PE_STATUS_WRITE_FAILURE;
        goto out;
    }

    FSEEK_OR_FAIL(section->file->fd, abs_pos, status, out);
    FWRITE_OR_FAIL(in, amount, section->file->fd, status, out);

    section->pos += amount;
out:
    return status;
}

PE_STATUS pefile_section_seek(struct pefile_section *section, uint32_t offset)
{
    PE_STATUS status = PE_STATUS_OK;
    section->pos = offset;
    return status;
}

static PE_STATUS pefile_load_dos_header(struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    int res = fread(&file->dos_header, sizeof(file->dos_header), 1, file->fd);
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

static PE_STATUS pefile_load_pe_header(struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    char sig[PE_SIGNATURE_SIZE];
    int res = -1;
    fseek(file->fd, file->dos_header.e_lfanew, SEEK_SET);
    res = fread(sig, PE_SIGNATURE_SIZE, 1, file->fd);
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
    FREAD_OR_FAIL(&file->pe_header, sizeof(file->pe_header), file->fd, status, out);

out:
    return status;
}

PE_STATUS pefile_save_header(struct pefile* file)
{
    PE_STATUS status = PE_STATUS_OK;
    
    FSEEK_OR_FAIL(file->fd, 0, status, out);
    FWRITE_OR_FAIL(&file->dos_header, sizeof(file->dos_header), file->fd, status, out);

    FSEEK_OR_FAIL(file->fd, file->dos_header.e_lfanew+PE_SIGNATURE_SIZE, status, out);
    FWRITE_OR_FAIL(&file->pe_header, sizeof(file->pe_header), file->fd, status, out);
    
    if (file->pe_header.size_of_optional_header != 0)
    {
        size_t size = file->pe_header.size_of_optional_header;
        FWRITE_OR_FAIL(&file->optional_header.standard_fields, sizeof(file->optional_header.standard_fields), file->fd, status, out);
        size -= sizeof(file->optional_header.standard_fields);
        if (file->optional_header.standard_fields.magic != PE_FILE_PE32_PLUS)
        {
            FWRITE_OR_FAIL(&file->optional_header.base_of_data, sizeof(file->optional_header.base_of_data), file->fd, status, out);
            size -= sizeof(file->optional_header.base_of_data);
        }

        // Is there image fields?
        if (size < sizeof(file->optional_header.image_fields))
        {
            goto out;
        }

        FWRITE_OR_FAIL(&file->optional_header.image_fields, sizeof(file->optional_header.image_fields), file->fd, status, out);
        size -= sizeof(file->optional_header.image_fields);
    }

out:
    return status;
}

static uint32_t pefile_sum_sections(struct pefile* file, uint32_t characteristics)
{
    uint32_t size = 0;
    for (int i = 0; i < file->pe_header.number_of_sections; i++)
    {
        if (file->section_headers[i].characteristics & characteristics)
        {
            size += file->section_headers[i].raw_size;
        }
    }
    return size;
}

static PE_STATUS pefile_add_section_header(struct pefile *file, struct pefile_section_header *to_add)
{
    PE_STATUS status = PE_STATUS_OK;
    struct pefile_section_header *headers = (struct pefile_section_header *)realloc(file->section_headers, (file->pe_header.number_of_sections+1) * sizeof(struct pefile_section_header));
    if (!headers)
    {
        status = PE_STATUS_MEMORY_ERROR;
        goto out;
    }

    // Copy our section to memory
    memcpy(&headers[file->pe_header.number_of_sections], to_add, sizeof(struct pefile_section_header));
    file->section_headers = headers;

    // Let's save the section header to disk
    uint32_t offset = file->offset_to_section_headers + (file->pe_header.number_of_sections * sizeof(struct pefile_section_header));
    FSEEK_OR_FAIL(file->fd, offset, status, out);
    FWRITE_OR_FAIL(&headers[file->pe_header.number_of_sections], sizeof(struct pefile_section_header), file->fd, status, out);


    // Update the number of sections
    uint32_t file_alignment = file->optional_header.image_fields.file_alignment;
    uint32_t virtual_address_end = to_add->virtual_address + to_add->virtual_size;
    uint32_t section_alignment = file->optional_header.image_fields.section_alignment;
    file->pe_header.number_of_sections += 1;
    file->optional_header.image_fields.size_of_image = virtual_address_end + (section_alignment - virtual_address_end) % section_alignment;
    file->optional_header.image_fields.size_of_headers = (file_alignment - offset) % file_alignment;
    file->optional_header.standard_fields.size_of_code = pefile_sum_sections(file, IMAGE_SCN_CNT_CODE);
    file->optional_header.standard_fields.size_of_initialized_data = pefile_sum_sections(file, IMAGE_SCN_CNT_INITIALIZED_DATA);
    file->optional_header.standard_fields.size_of_uninitialized_data = pefile_sum_sections(file, IMAGE_SCN_CNT_UNINITIALIZED_DATA);

    pefile_save_header(file);

out:
    return status;
}
struct pefile_section *pefile_section_create(struct pefile *file, const char *name, const void *in, size_t size, uint32_t characteristics)
{
    PE_STATUS status = PE_STATUS_OK;
    struct pefile_section *section = NULL;
    void* tmp = NULL;
    char _name[PE_SECTION_NAME_SIZE];
    memcpy(_name, name, strnlen(name, sizeof(_name)));

    struct pefile_section_header *last_header = pefile_section_header_last(file);
    if (!last_header)
    {
        // Note that EXE files with no sections cannot be managed by this version of the software
        goto out;
    }

    uint32_t section_alignment = file->optional_header.image_fields.section_alignment;
    uint32_t virtual_address = last_header->virtual_address + last_header->virtual_size;
    uint32_t virtual_address_aligned = virtual_address + (section_alignment - virtual_address) % section_alignment;
    uint32_t raw_address = last_header->raw_address + last_header->raw_size;
    uint32_t raw_size = size + ((section_alignment - size) % section_alignment);
    struct pefile_section_header header;
    memset(&header, 0, sizeof(header));
    memcpy(header.name, _name, sizeof(_name));
    header.virtual_address = virtual_address_aligned;
    header.virtual_size = size;
    header.raw_address = raw_address;
    header.raw_size = raw_size;
    header.characteristics = characteristics;
    status = pefile_add_section_header(file, &header);
    if (status != PE_STATUS_OK)
    {
        goto out;
    }

    // Now we write the data
    tmp = malloc(raw_size);
    memset(tmp, 0, raw_size);
    memcpy(tmp, in, size);
    FSEEK_OR_FAIL(file->fd, header.raw_address, status, out);
    FWRITE_OR_FAIL(tmp, raw_size, file->fd, status, out);

    section = pefile_section_open_by_header(file, &header);

out:
    if (tmp)
        free(tmp);
    
    return section;
}

PE_STATUS pefile_load(const char *filename, const char *mode, struct pefile *file)
{
    PE_STATUS status = PE_STATUS_OK;
    FILE *f = fopen(filename, mode);
    if (!f)
    {
        status = PE_STATUS_OPEN_FAILURE;
        goto out;
    }

    file->fd = f;
    file->filename = filename;

    status = pefile_load_dos_header(file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_pe_header(file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_optional_header(file);
    if (status != PE_STATUS_OK)
        goto out;

    status = pefile_load_section_headers(file);
    if (status != PE_STATUS_OK)
        goto out;

out:
    return status;
}