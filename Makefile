CC=gcc
CFLAGS=-Wall
FLAGS = -lelf -lcrypto -lcapstone
LIBELF = libelf64
OBJ1 = libelf64.o
OBJ2 = binscan.o
BINSCAN = binscan

all: $(BINSCAN)

$(BINSCAN): $(OBJ1) $(OBJ2)
	$(CC) $(CFLAGS) -o $(BINSCAN) $(OBJ1) $(OBJ2) $(FLAGS)

$(OBJ1): libelf64.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ1)

$(OBJ2): binscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ2)

clean:
	rm *.o 
