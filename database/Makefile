CFLAG = -g -c -std=c++14 -fmax-errors=1 -pthread -fPIC
INCLUDE = -I../ -I../src/ -I../framework/ -I/usr/include/jsoncpp
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.database.o, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.x, $(wildcard *.cpp))

all : $(OBJ) $(MAIN_OBJ)

../obj/%.database.o : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
