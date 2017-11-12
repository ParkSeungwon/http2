CC = g++
OBJ = $(wildcard *.o)
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
TEST = $(patsubst %.t, ../%.x, $(wildcard *.t))
gtkmmLIB = $(shell pkg-config gtkmm-3.0 --libs)

all : $(EXE)
test : $(TEST)

../%.x : %.x $(OBJ)
	$(CC) -o $@ $< $(OBJ) -lpthread -lmysqlcppconn

../%.x : %.t $(OBJ)
	$(CC) -o $@ $< $(OBJ) -lpthread -lmysqlcppconn
