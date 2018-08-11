all : 
	echo "const char certificate[] = R\"cert(" > tls/cert.h
	cat server-cert.pem >> tls/cert.h
	echo ")cert\";" >> tls/cert.h
	make -C src/
	make -C framework/
	make -C database/
	make -C tls/
	make -C tst/
	make -C obj/
	./catch.x

clean :
	rm obj/*.? *.x

