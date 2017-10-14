all : 
	make -C src/
	make -C obj/
	make -C tst/

PHONY : clean test

clean :
	rm obj/*.?

test : 
	make -C obj/ test
