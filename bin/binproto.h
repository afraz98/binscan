#include<openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#ifndef BIN_PROTO
#define BIN_PROTO
#define LONGEST_OPCODE 10
#define MAX_INSTRUCTIONS 1000

typedef enum{
  SHA1_RECORD,
  I_BUFFER,
  RENTROPY,
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
  Instruction instructions[MAX_INSTRUCTIONS];
  int ninstructions; 
} IBuffer;

typedef struct{
  double entropy;
} RenyiEntropy;

typedef struct{
  uint8_t md5[MD5_DIGEST_LENGTH];
} MD5Record; 
#endif 
