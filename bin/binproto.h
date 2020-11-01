#include<openssl/sha.h>

#ifndef BIN_PROTO
#define BIN_PROTO
#define LONGEST_OPCODE 10
#define MAX_INSTRUCTIONS 1000

typedef enum{
  SHA1_RECORD,
  I_BUFFER,
} EntryType;

typedef struct{
  char file_name[256];
  int data_length;
} FileHeader;

typedef struct{
  EntryType et;
  uint8_t sha1[SHA_DIGEST_LENGTH];
} SHA1Record;

typedef struct{
  char instruction[LONGEST_OPCODE];
  int instruction_calls;
} Instruction;

typedef struct{
  EntryType et; 
  Instruction instructions[MAX_INSTRUCTIONS];
  int ninstructions; 
} IBuffer;
#endif 
