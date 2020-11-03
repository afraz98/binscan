#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include "bin/libelf64.h"
#include <string.h>
#include "bin/openanalysis.h"

void printHelp(){
  printf("Welcome to Binscan!\n\n");
  printf("Current supported options:\n\n");

  printf("-help: Print information on binscan\n");
  printf("-analyze: Analyze ELF-64 binary. Requires file argument. Example call: ./binscan -analyze binary\n");
  printf("-help: Open binary file produced by analyze command. !! Password Authentication necessary !!\n"); 
}

int main(int argc, char **argv){
  if(argc == 1){
    printf("Invalid arguments. Type './binscan -help' for more information.\n");
    exit(0);
  }
  
  if(strcmp(argv[1], "-analyze") == 0 && argc == 3) parseElf(argv[2]); //Parse ELF-64 object
  else if(strcmp(argv[1], "-help") == 0) printHelp(); //Print help for binscan utility
  else if(strcmp(argv[1], "-open") == 0) openAnalysis(argv[2]); //Open binary file containing analysis 
  else printf("Invalid arguments. Type './binscan -help' for more information.\n");
  return 0;
}
