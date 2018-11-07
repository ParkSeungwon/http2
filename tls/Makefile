CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread -Wcpp
INCLUDE = -I../ -I/usr/include/jsoncpp -I/usr/include/botan-2
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.o, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.x, $(wildcard *.cpp))

all : $(OBJ) $(MAIN_OBJ)

../obj/%.o : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

