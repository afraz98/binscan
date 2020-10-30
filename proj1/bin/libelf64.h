#include <err.h>
#include <fcntl.h>
#include <gelf.h>


#define PRINT_FMT "    %-20s 0x%jx"
#define PRINT_FIELD(N) do { printf(PRINT_FMT , #N,(uintmax_t) ehdr.N);} while (0)
#define PRINT_PHDRFIELD(N) do {printf(PRINT_FMT, #N, (uintmax_t) phdr.N);} while(0)

int checkElf64(Elf *e);
Elf *openElf(char *file, int fd);
void printElfHeader(Elf *e);
void printp_type(size_t pt);
void printProgramHeaders(Elf *e);
void parseElf(int argc, char** argv); 
