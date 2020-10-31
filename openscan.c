#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bin/openanalysis.h"
#define PASSWORD_LENGTH 20


void analysisUser(char *file){
  printf("Analyzing file as user.\n");
}

void analysisAdmin(char *file){
  printf("Analyzing file as admin.\n"); 
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
