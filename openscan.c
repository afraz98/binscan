#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bin/openanalysis.h"
#include "bin/binproto.h"

#define PASSWORD_LENGTH 200
void analysisUser(char *file){
  FILE *input;
  FileHeader fh;
  SHA1Record sharecord;
  IBuffer ib;
  RenyiEntropy r;
  SHA256Record sha256record; 
  
  printf("Analyzing file as user..\n\n");
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
  } printf("\n\n");

  for(int i = 0; i < ib.ninstructions; i++){
    printf("%s\t%d\n", ib.instructions[i].instruction, ib.instructions[i].instruction_calls);
  } printf("\n");

  printf("Renyi Entropy: %lf\n\n", r.entropy);

  printf("SHA256: ");
  for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", sha256record.sha256[i]);
  } printf("\n"); 
}


int comparePassword(char *input){
  char *user = "letmein";
  if(strlen(input) == strlen(user)){
    for(int i = 0; i < strlen(input); i++){
      if(!compareCharacters(input[i], user[i])){ return 0; } 
    } return 1; 
  } else if(strlen(input) == strlen(ADMINPASSWORD)){
    for(int i = 0; i < strlen(ADMINPASSWORD); i++){
      if(!compareCharacters(input[i], ADMINPASSWORD[i])){return 0; }
    } return 2; 
  } else return 0; 
}

void analysisAdmin(char *file){
    FILE *input;
  FileHeader fh;
  SHA1Record sharecord;
  IBuffer ib;
  RenyiEntropy r;
  SHA256Record sha256record;

  printf("Analyzing file as admin ..\n\n");
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
  } printf("\n\n");

  for(int i = 0; i < ib.ninstructions; i++){
    printf("%s\t%d\n", ib.instructions[i].instruction, ib.instructions[i].instruction_calls);
  } printf("\n");

  printf("Renyi Entropy: %lf\n\n", r.entropy);

  printf("SHA256: ");
  for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", sha256record.sha256[i]);
  } printf("\n");

}

void openAnalysis(char *file){
  char password[PASSWORD_LENGTH];
  int userPrivilege = 0; 
  password[0] = '\0';
  
  printf("Please enter the password.\n");
  fgets(password, PASSWORD_LENGTH, stdin);
  password[strlen(password)-1] = '\0'; 

  if(comparePassword(password) == 2){
    printf("Admin access granted.\n");
    userPrivilege = 2;
  } else if (comparePassword(password) == 1){
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
