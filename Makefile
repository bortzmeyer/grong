include $(GOROOT)/src/Make.inc

TARBALL=/tmp/grong.tar.gz

all: grong

test: grong
	./grong -debug=4 -servername "grong.dns.test"

server.$O: responder.$O types.$O

responder.$O: types.$O

%.$O: %.go 
	${GC} $<

grong: server.$O
	${LD} -o $@ server.$O

dist: distclean
	(cd ..; tar czvf ${TARBALL} grong/*)

clean:
	rm -f grong *.$O *.a

distclean: clean
	rm -f *~ responder.go