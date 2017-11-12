CFLAG = -g -c -std=c++14 -fmax-errors=1 -pthread
INCLUDE = -I../ -I../src/ -I../framework/ -I../database/ -I/usr/include/jsoncpp
CC = g++
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.t, $(wildcard *.cpp))

all : $(MAIN_OBJ)

../obj/%.t : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
