#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bin/openanalysis.h"
#include "bin/binproto.h"

#define PASSWORD_LENGTH 20

void analysisUser(char *file){
  FILE *input;
  FileHeader fh;
  SHA1Record sharecord;
  IBuffer ib;
  RenyiEntropy r;
  MD5Record mdrecord; 
  
  printf("Analyzing file as user..\n\n");
  input = fopen(file, "r");
  fread(&fh, sizeof(FileHeader), 1, input);
  fread(&sharecord, sizeof(SHA1Record), 1, input);
  fread(&ib, sizeof(IBuffer), 1, input);
  fread(&r, sizeof(RenyiEntropy), 1, input); 
  fread(&mdrecord, sizeof(MD5Record), 1, input);
  
  printf("Analysis of %s binary\n\n", fh.file_name);
  printf("SHA1: ");
  for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
    printf("%02x", sharecord.sha1[i]);
  } printf("\n\n");

  for(int i = 0; i < ib.ninstructions; i++){
    printf("%s\t%d\n", ib.instructions[i].instruction, ib.instructions[i].instruction_calls);
  } printf("\n");

  printf("Renyi Entropy: %lf\n\n", r.entropy);

  printf("MD5: ");
  for(unsigned int i = 0; i < MD5_DIGEST_LENGTH; i++){
    printf("%02x", mdrecord.md5[i]);
  } printf("\n"); 
}

void analysisAdmin(char *file){
  printf("Analyzing file as admin..\n\n"); 
}

void openAnalysis(char *file){
  char password[PASSWORD_LENGTH];
  int userPrivilege = 0; 
  password[0] = '\0';
  
  char *admin = "password123";
  char *user = "letmein";
  
  printf("Please enter the password.\n");
  fgets(password, PASSWORD_LENGTH, stdin);
  password[strlen(password)-1] = '\0'; 
  
  if(strcmp(password, admin) == 0){
    printf("Admin access granted.\n");
    userPrivilege = 2;
  } else if (strcmp(password, user) == 0){
    printf("User access granted.\n");
    userPrivilege = 1; 
  } else {
    printf("Access denied.\n");
    userPrivilege = 0; 
  }

  switch(userPrivilege){
  case 0:
    exit(0);
    break;
  case 1:
    analysisUser(file);
    break;
  case 2:
    analysisAdmin(file);
    break;
  }
}
