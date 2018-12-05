CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread
INCLUDE = -I../ -I../src/ -I../database/ -I/usr/include/p11-kit-1
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.o, $(wildcard *.cc))
OOBJ = $(patsubst %.cc, ../obj/%.O, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.x, $(wildcard *.cpp))

all : $(OBJ) $(MAIN_OBJ) $(OOBJ)

../obj/%.o : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.O : %.cc 
	$(CC) $(INCLUDE) -fPIC $(CFLAG) $< -o $@

../obj/%.x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
