#include<openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#ifndef BIN_PROTO
#define BIN_PROTO
#define LONGEST_OPCODE 15
#define MAX_INSTRUCTIONS 10000

typedef enum {
  SHA1_RECORD,
  I_BUFFER,
  RENTROPY,
} EntryType; // Enum of FileHeader entry types 

typedef struct {
  char file_name[256];
  int data_length;
} FileHeader; // File header with file name and data length 

typedef struct {
  EntryType et;
  uint8_t sha1[SHA_DIGEST_LENGTH];
} SHA1Record; // SHA1 Record with byte array containing checksum and FileHeader entry type

typedef struct {
  char instruction[LONGEST_OPCODE];
  int instruction_calls;
} Instruction; // Instruction object with string opcode and number of instruction calls

typedef struct { 
  Instruction instructions[MAX_INSTRUCTIONS];
  int ninstructions; 
} IBuffer; // Instruction buffer containing number of instructions and instruction array

typedef struct {
  double entropy;
} RenyiEntropy; // Renyi Entropy calculation

typedef struct {
  uint8_t sha256[SHA256_DIGEST_LENGTH];
} SHA256Record; // SHA256 byte array
#endif 
