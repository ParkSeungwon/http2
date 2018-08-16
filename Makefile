all : tls/cert.h others

tls/cert.h : server-cert.pem
	echo "const char certificate[] = R\"cert(" > $@
	cat $< >> $@
	echo ")cert\";" >> $@

others:
	incltouch.x
	make -C src/
	make -C framework/
	make -C database/
	make -C tls/
	make -C tst/
	make -C obj/
	./catch.x

clean :
	rm obj/*.? *.x

