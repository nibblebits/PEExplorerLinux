FLAGS= -g
INCLUDES = -I ./include
OBJECTS = ./build/pefile.o
all: ${OBJECTS}
	gcc ${INCLUDES} ./src/main.c ${FLAGS} ${OBJECTS} -o ./bin/main

./build/pefile.o:./src/pefile.c
	gcc -c ${INCLUDES} ./src/pefile.c ${FLAGS} -o ./build/pefile.o


clean:
	rm -rf ${OBJECTS}

