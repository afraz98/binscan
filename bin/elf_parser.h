#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include "bin_proto.h"

#ifndef ELF_PARSER
#define ELF_PARSER

typedef unsigned char byte; 

// Verify that the ELF object to be parsed is indeed an ELF-64 object.
int check_elf64(Elf* e);

// Attempt to read ELF Struct from file
Elf *open_elf(char* file, int fd);

// Primary driver function for ELF-64 parsing
void parse_elf(char* file); 

// Use section header to find text section
GElf_Shdr find_text_section(Elf* e, Elf_Scn** s); 

// Print SHA1 checksum utilizing OpenSSL
void print_sha1(Elf* e, byte* sha_value); 

// Print SHA256 checksum utilizing OpenSSL
SHA256Record print_sha256(Elf *e); 

// Parse text section for data buffer, call print instructions
IBuffer parse_text_section(Elf *e); 

// Print unique instructions with call counts with Capstone library
IBuffer print_instructions(unsigned char* buffer, size_t buffersize, uint64_t address); 

//Calculate Renyi entropy from text section bytes
RenyiEntropy calculate_renyi_entropy(Elf* e); 

/*  Output SHA1 and FileHeader to file 
    (Note: Later structures written to file from parseElf()) */
int fill_file_buffer(uint8_t* buffer, char* argfile, uint8_t* sha1);

#endif