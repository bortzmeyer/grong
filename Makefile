include $(GOROOT)/src/Make.inc

TARBALL=/tmp/grong.tar.gz
DEFAULTPORT=8053

all: grong

test: grong
	@echo "Running server on port $(DEFAULTPORT)..."
	./grong -debug=4 -nodaemon -address ":$(DEFAULTPORT)" -servername "grong.dns.test"

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