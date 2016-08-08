CC=arm-linux-gcc

all:executable

debug: CC += -g -DDEBUG
debug: executable

executable: dukpt.c
	$(CC) dukpt.c -o dukpt -lfepkcs11 -lcrypto
	fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 --infile dukpt
	
.PHONY: clean
clean:
	rm -f dukpt dukpt.backup
