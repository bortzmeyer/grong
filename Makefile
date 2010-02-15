include $(GOROOT)/src/Make.$(GOARCH)

TARBALL=/tmp/grong.tar.gz

all: server

test: server
	./server -debug=4

server.$O: responder.$O types.$O

responder.$O: types.$O

%.$O: %.go 
	${GC} $<

server: server.$O
	${LD} -o $@ server.$O

dist: distclean
	(cd ..; tar czvf ${TARBALL} grong/*)

clean:
	rm -f server *.$O

distclean: clean
	rm -f *~ responder.go