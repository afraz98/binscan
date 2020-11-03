#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include "binproto.h"

typedef unsigned char byte; 

//Check if Elf Object is ELF-64
int checkElf64(Elf *e);

//Attempt to read ELF Struct from file
Elf *openElf(char *file, int fd);

//Primary driver function for ELF-64 parsing
void parseElf(char* file); 

//Use section header to find text section
GElf_Shdr findTextSection(Elf *e, Elf_Scn **s); 

//Print SHA1 checksum utilizing OpenSSL
void printSHA1(Elf *e, byte *sha_value); 

//Print SHA256 checksum utilizing OpenSSL
SHA256Record printSHA256(Elf *e); 

//Parse text section for data buffer, call print instructions
IBuffer parseSectionText(Elf *e); 

//Print unique instructions with call counts with Capstone library
IBuffer printInstructions(unsigned char* buffer, size_t buffersize, uint64_t address); 

//Calculate Renyi entropy from text section bytes
RenyiEntropy calculateEntropy(Elf *e); 

//Output SHA1 and FileHeader to file 
//(Note: Later structures written to file from parseElf())
int fillFileBuffer(uint8_t *buffer, char *argfile, uint8_t *sha1);
