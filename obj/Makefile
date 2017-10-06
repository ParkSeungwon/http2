CC = g++
OBJ = $(wildcard *.o)
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
gtkmmLIB = $(shell pkg-config gtkmm-3.0 --libs)

all : $(EXE)

../%.x : %.x $(OBJ)
	$(CC) -o $@ $< $(OBJ) -lzezeon -lpthread -lmysqlcppconn


