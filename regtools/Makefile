all: ../bin/regtool ../bin/pasco

../bin/regtool: regtool.c registry.c misc.c ntreg.c
	gcc -g -o ../bin/regtool regtool.c ntreg.c registry.c misc.c

../bin/pasco: pasco.c
	gcc -g -o ../bin/pasco pasco.c -lm
clean:
	rm -f ../bin/regtool ../bin/pasco
