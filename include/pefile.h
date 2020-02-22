#ifndef PEFILE_H
#define PEFILE_H
#include <stdint.h>



#define PE_SIGNATURE_SIZE 4

#define PE_CHARACTERISTIC_FILE_EXECUTEABLE 0x02
#define PE_CHARACTERISTIC_FILE_IS_DLL 0x2000
#define PE_CHARACTERISTIC_FILE_IS_SYSTEM 0x1000
#define PE_CHARACTERISTIC_RELOCATION_INFO_STRIPPED 0x0001
#define PE_CHARACTERISTIC_LINE_NUMBERS_STRIPPED 0x0004
#define PE_CHARACTERISTIC_LOCAL_SYMBOLS_STRIPPED 0x0008
#define PE_CHARACTERISTIC_AGGRESSIVE_TRIM 0x0010
#define PE_CHARACTERISTIC_CAN_HANDLE_2GB_PLUS 0x0020
#define PE_CHARACTERISTIC_BYTES_RESERVED_LOW 0x0080
#define PE_CHARACTERISTIC_32_BIT_WORD_MACHINE 0x0100
#define PE_CHARACTERISTIC_COPY_RUN_FILE_IF_EXTERNAL_MEDIA 0x0400
#define PE_CHARACTERISTIC_COPY_RUN_ON_SWAP_IF_NET_FILE 0x0800
#define PE_CHARACTERISTIC_UP_MACHINE_ONLY 0x4000
#define PE_CHARACTERISTIC_BYTES_OF_MACHINE_WORD_RESERVED_HIGH 0x8000

#define PE_CHECK_CHARACTERISTIC_LEAVE_IF_FOUND(c, result, flag, message, out) \
    if (*c & flag)                                                            \
    {                                                                         \
        result = message;                                                     \
        *c &= ~flag;                                                          \
        goto out;                                                             \
    }



/**
 * Reads from the provided file and on failure changes the provided status
 * and jumps to out.
 */
#define FREAD_OR_FAIL(dst, size, file, status, out) \
   {\
     int res = fread(dst, size, 1, file);   \
     if (!res) \
     {\
       status = PE_STATUS_READ_FAILURE;\
       goto out; \
     }  \
   } \


#define PE_FILE_NORMAL_EXECUTABLE 0x10B
#define PE_FILE_ROM_IMAGE  0x107
#define PE_FILE_PE32_PLUS 0x20B


typedef uint16_t PE_STATUS;
enum
{
    PE_STATUS_OK,
    PE_STATUS_DOS_HEADER_READ_FAILURE,
    PE_STATUS_INVALID_PE_FILE,
    PE_STATUS_READ_FAILURE,
    PE_STATUS_OPTIONAL_HEADER_BAD_MAGIC,
    PE_STATUS_NO_OPTIONAL_HEADER
};

struct pefile_dos_header
{
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t eovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct pefile_pe_header
{
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct pefile_pe_optional_header_standard_fields
{
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
};

struct pefile_pe_optional_header_image_specific_fields
{
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};

struct pefile_pe_optional_header
{

    struct pefile_pe_optional_header_standard_fields standard_fields;
    uint32_t base_of_data;
    struct pefile_pe_optional_header_image_specific_fields image_fields;
};

struct pefile
{
    struct pefile_dos_header dos_header;
    struct pefile_pe_header pe_header;
    struct pefile_pe_optional_header optional_header;
};

void pefile_init(struct pefile *file);
PE_STATUS pefile_load(const char *filename, const char *mode, struct pefile *file);
const char *pefile_characteristic(uint16_t *c);

#endif