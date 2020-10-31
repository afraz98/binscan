#ifndef BIN_PROTO
#define BIN_PROTO

#include <openssl/sha.h>

typedef enum{
  SHA1_RECORD,
} EntryType;

typedef struct{
  char file_name[256];
  int data_length;
} FileHeader;

typedef struct{
  EntryType et;
  uint8_t sha1[SHA_DIGEST_LENGTH];
} SHA1Record;

#endif 
