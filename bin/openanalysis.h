//To be called by binscan driver
void openAnalysis(char *file); 

//Perform analysis as admin
void analysisAdmin(char *file);

//Perform analysis as user 
void analysisUser(char *file);

//NASM Assembly function comparing characters 
extern long compareCharacters(char a, char b);


#define ADMINPASSWORD "notthepassword"
