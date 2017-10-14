all : 
	make -C src/
	make -C obj/
	make -C tst/

PHONY : clean test

clean :
	rm obj/*.x obj/*.o  *.x obj/*.t

ls :
	echo $(EXE)

test : 
	make -C obj/ test
