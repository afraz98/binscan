# Standard GCC Flags 
CC=gcc
CFLAGS=-Wall

# External libraries for compilation
FLAGS = -lelf -lcrypto -lcapstone -lm
LIBELF = libelf64

# Object files for main executable
OBJ1 = libelf64.o
OBJ2 = binscan.o
OBJ3 = open_analysis.o
OBJ4 = encrypt.o

# Binscan: Main executable target
BINSCAN = binscan

# Main executable target
all: $(BINSCAN)
$(BINSCAN): $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5)
	$(CC) $(CFLAGS) -o $(BINSCAN) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(FLAGS)

# Compile ELF-64 Binary Parsing
$(OBJ1): libelf64.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ1)

# Compile Command-Line interface handler
$(OBJ2): binscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ2)

# Compile Analysis File Opener
$(OBJ3): open_analysis.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ3)

$(OBJ4): encrypt.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ4) 

# Remove unnecessary object files
clean:
	rm *.o
