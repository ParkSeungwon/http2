all : 
	make -C src/
	make -C obj/

PHONY : clean test

clean :
	rm obj/*.? *.x

test : 
	make -C tst/
	make -C obj/ test
