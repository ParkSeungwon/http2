CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread -fPIC
INCLUDE = -I../ -I/usr/include/jsoncpp -I/usr/include/python2.7
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.O, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.x, $(wildcard *.cpp))

all : $(OBJ) $(MAIN_OBJ) 

../obj/%.O : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
