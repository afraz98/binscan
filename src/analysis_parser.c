#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analysis_parser.h"
#include "bin_proto.h"

void parse_analysis(char* file){
  FILE *input;
  FileHeader fh;
  SHA1Record sharecord;
  IBuffer ib;
  RenyiEntropy r;
  SHA256Record sha256record;

  input = fopen(file, "r");
  fread(&fh, sizeof(FileHeader), 1, input);
  fread(&sharecord, sizeof(SHA1Record), 1, input);
  fread(&ib, sizeof(IBuffer), 1, input);
  fread(&r, sizeof(RenyiEntropy), 1, input);
  fread(&sha256record, sizeof(SHA256Record), 1, input);

  printf("Analysis of %s binary\n\n", fh.file_name);
  printf("SHA1: ");
  
  for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
    printf("%02x", sharecord.sha1[i]);
  }

  for(int i = 0; i < ib.ninstructions; i++){
    printf("%s\t%d\n", ib.instructions[i].instruction, ib.instructions[i].instruction_calls);
  }
  
  printf("Renyi Entropy: %lf\n", r.entropy);
  printf("SHA256: ");
  for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", sha256record.sha256[i]);
  } printf("\n");

}

