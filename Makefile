CC=gcc
CFLAGS=-Wall
FLAGS = -lelf -lcrypto -lcapstone -lm
LIBELF = libelf64
OBJ1 = libelf64.o
OBJ2 = binscan.o
OBJ3 = openscan.o
BINSCAN = binscan

all: $(BINSCAN)

$(BINSCAN): $(OBJ1) $(OBJ2) $(OBJ3)
	$(CC) $(CFLAGS) -o $(BINSCAN) $(OBJ1) $(OBJ2) $(OBJ3) $(FLAGS)

$(OBJ1): libelf64.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ1)

$(OBJ2): binscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ2)

$(OBJ3): openscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ3)

clean:
	rm *.o binscan *.bin
