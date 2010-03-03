/* Main program for the GRONG authoritative name server
   Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>
*/

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"./responder"
	"strings"
	"./types"
)

var debug int

func serialize(packet types.DNSpacket) []byte {
	result := make([]byte, 512)
	// ID
	binary.BigEndian.PutUint16(result[0:2], packet.Id)
	// Misc flags...
	result[2] = 0x80 // TODO: why this value?
	result[3] = byte(packet.Rcode)
	binary.BigEndian.PutUint16(result[4:6], packet.Qdcount)
	// Ancount
	binary.BigEndian.PutUint16(result[6:8], packet.Ancount)
	// Nscount
	result[8] = 0
	result[9] = 0
	// Arcount
	result[10] = 0
	result[11] = 0
	if len(packet.Qsection) != 1 {
		fmt.Printf("Fatal: Qsection's length is not 1: %d\n", len(packet.Qsection))
		os.Exit(1) // TODO: better handling
	}
	encoded_qname := types.Encode(packet.Qsection[0].Qname)
	last := 0
	for i, c := range encoded_qname {
		result[12+i] = c
		last = i
	}
	binary.BigEndian.PutUint16(result[12+last+1:], packet.Qsection[0].Qtype)
	binary.BigEndian.PutUint16(result[12+last+3:], packet.Qsection[0].Qclass)
	last = 12 + last + 5
	for rrnum, rr := range packet.Asection {
		encoded_qname := types.Encode(packet.Asection[rrnum].Name)
		n := 0
		for i, c := range encoded_qname {
			result[last+i] = c
			n++
		}
		binary.BigEndian.PutUint16(result[last+n:last+n+2], rr.Type)
		binary.BigEndian.PutUint16(result[last+n+2:last+n+4], rr.Class)
		binary.BigEndian.PutUint32(result[last+n+4:last+n+8], rr.TTL)
		binary.BigEndian.PutUint16(result[last+n+8:last+n+10], uint16(len(rr.Data)))
		last = last + n + 10
		n = 0
		for i, c := range packet.Asection[rrnum].Data {
			result[last+i] = c
			n++
		}
		last = last + n
	}
	return result[0:last]
}

func readShortInteger(buf *bytes.Buffer) uint16 {
	slice := make([]byte, 2)
	n, error := buf.Read(slice[0:2])
	if error != nil || n != 2 {
		fmt.Printf("Error in Read of an int16: %s (%d bytes read)\n", error, n)
		os.Exit(1) // TODO: should handle it better?
	}
	return binary.BigEndian.Uint16(slice[0:2])
}

func parse(buf *bytes.Buffer) types.DNSpacket {
	var packet types.DNSpacket
	packet.Valid = false
	packet.Id = readShortInteger(buf)
	dnsmisc := readShortInteger(buf)
	qr := (dnsmisc & 0x8000) >> 15
	packet.Query = false
	if qr == 0 {
		packet.Query = true
	}
	packet.Opcode = uint((dnsmisc >> 11) & 0x000F)
	rd := (dnsmisc & 0x0100) >> 8
	packet.Recursion = false
	if rd == 1 {
		packet.Recursion = true
	}
	packet.Rcode = uint(dnsmisc & 0x000F)
	packet.Qdcount = readShortInteger(buf)
	packet.Ancount = readShortInteger(buf)
	packet.Nscount = readShortInteger(buf)
	packet.Arcount = readShortInteger(buf)
	over := false
	labels_max := make([]string, 63)
	labels := labels_max[0:0]
	nlabels := 0
	for !over {
		labelsize, error := buf.ReadByte()
		if error != nil {
			if error == os.EOF {
				return packet
			} else {
				fmt.Printf("Error in ReadByte: %s\n", error)
				os.Exit(1) // TODO: should handle it better
			}
		}
		if labelsize == 0 {
			over = true
			break
		}
		label := make([]byte, labelsize)
		n, error := buf.Read(label)
		if error != nil || n != int(labelsize) {
			if error == nil {
				// Client left after leaving only a few bytes
				return packet
			} else {
				fmt.Printf("Error in Read %d bytes: %s\n", n, error)
				os.Exit(1) // TODO: should handle it better
			}
		}
		nlabels += 1
		labels = labels[0:nlabels]
		labels[nlabels-1] = string(label)
	}
	packet.Qsection = make([]types.Qentry, packet.Qdcount)
	packet.Qsection[0].Qname = strings.Join(labels, ".")
	packet.Qsection[0].Qtype = readShortInteger(buf)
	packet.Qsection[0].Qclass = readShortInteger(buf)
	packet.Valid = true
	return packet
}

func generichandle(buf *bytes.Buffer, remaddr net.Addr) (response types.DNSpacket, noresponse bool) {
	var query types.DNSquery
	noresponse = true
	packet := parse(buf)
	if !packet.Valid { // Invalid packet or client too impatient
		return
	}
	if debug > 2 {
		fmt.Printf("Query is %t, Opcode is %d, Recursion is %t, Rcode is %d\n",
			packet.Query, packet.Opcode, packet.Recursion, packet.Rcode)
		fmt.Printf("FQDN is %s, type is %d, class is %d\n", packet.Qsection[0].Qname, packet.Qsection[0].Qtype, packet.Qsection[0].Qclass)
	}
	if packet.Query && packet.Opcode == types.STDQUERY {
		if debug > 2 {
			fmt.Printf("Replying with ID %d...\n", packet.Id)
		}
		noresponse = false
		response.Id = packet.Id
		response.Query = false
		response.Opcode = packet.Opcode
		response.Qdcount = 1 // Or packet.Qdcount ?
		response.Qsection = make([]types.Qentry, response.Qdcount)
		response.Qsection[0].Qname = packet.Qsection[0].Qname
		response.Qsection[0].Qclass = packet.Qsection[0].Qclass
		response.Qsection[0].Qtype = packet.Qsection[0].Qtype
		query.Client = remaddr
		query.Qname = packet.Qsection[0].Qname
		query.Qclass = packet.Qsection[0].Qclass
		query.Qtype = packet.Qsection[0].Qtype
		desiredresponse := responder.Respond(query)
		response.Rcode = desiredresponse.Responsecode
		response.Ancount = uint16(len(desiredresponse.Asection))
		if response.Ancount > 0 {
			response.Asection = desiredresponse.Asection
		}
		return
	}
	// Else, ignore the incoming query. May be we should reply REFUSED instead?
	noresponse = true
	return
}

func udphandle(conn *net.UDPConn, remaddr net.Addr, buf *bytes.Buffer) {
	var response types.DNSpacket
	if debug > 1 {
		fmt.Printf("%d bytes packet from %s\n", buf.Len(), remaddr)
	}
	response, noresponse := generichandle(buf, remaddr)
	if !noresponse {
		binaryresponse := serialize(response)
		_, error := conn.WriteTo(binaryresponse, remaddr)
		if error != nil {
			fmt.Printf("Error in Write: %s\n", error)
			os.Exit(1) // TODO: should handle it better
		}
	}
	// Else, ignore the incoming packet. May be we should reply REFUSED instead?
}

func tcphandle(connection net.Conn) {
	if debug > 1 {
		fmt.Printf("TCP connection accepted from %s\n", connection.RemoteAddr())
	}
	smallbuf := make([]byte, 2)
	n, error := connection.Read(smallbuf)
	if error != nil {
		fmt.Printf("Cannot read message length from TCP connection: %s\n", error)
		os.Exit(1) // TODO: should handle it better
	}
	msglength := binary.BigEndian.Uint16(smallbuf) // RFC 1035, section 4.2.2 "TCP usage"
	message := make([]byte, msglength)
	n, error = connection.Read(message)
	if error != nil {
		fmt.Printf("Cannot read message from TCP connection with %s: %s\n", connection.RemoteAddr(), error)
		os.Exit(1) // TODO: should handle it better
	}
	if debug > 1 {
		fmt.Printf("%d bytes read from %s\n", n, connection.RemoteAddr())
	}
	response, noresponse := generichandle(bytes.NewBuffer(message), connection.RemoteAddr())
	if !noresponse {
		binaryresponse := serialize(response)
		shortbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(shortbuf, uint16(len(binaryresponse)))
		n, error := connection.Write(shortbuf)
		if n != 2 || error != nil {
			fmt.Printf("Error in TCP message length Write: %s\n", error)
			os.Exit(1) // TODO: should handle it better
		}
		n, error = connection.Write(binaryresponse)
		if error != nil {
			fmt.Printf("Error in TCP message Write: %s\n", error)
			os.Exit(1) // TODO: should handle it better
		}
	}
	connection.Close() // In theory, we may have other requests. We clearly violate the RFC by not waiting for them. TODO
}

func tcpListener(address *net.TCPAddr, comm chan bool) {
	listener, error := net.ListenTCP("udp", address)
	if error != nil {
		fmt.Printf("Cannot listen: %s\n", error)
		os.Exit(1)
	}
	for {
		connection, error := listener.Accept()
		if error != nil {
			fmt.Printf("Cannot accept TCP connection: %s\n", error)
			os.Exit(1) // TODO: should handle it better
		}
		go tcphandle(connection)
	}
	listener.Close()
	comm <- true
}

func udpListener(address *net.UDPAddr, comm chan bool) {
	listener, error := net.ListenUDP("udp", address)
	if error != nil {
		fmt.Printf("Cannot listen: %s\n", error)
		os.Exit(1)
	}
	for {
		message := make([]byte, 512) // 512 is a reasonable upper limit
		// for *incoming* queries
		n, remaddr, error := listener.ReadFrom(message)
		if error != nil {
			fmt.Printf("Cannot read UDP from %s: %s\n", remaddr.String(), error)
			os.Exit(1) // TODO: should handle it better
		}
		buf := bytes.NewBuffer(message[0:n])
		go udphandle(listener, remaddr, buf)
	}
	listener.Close()
	comm <- true
}

func main() {
	debugptr := flag.Int("debug", 0, "Set the debug level, the higher, the more verbose")
	listen := flag.String("address", ":8053", "Set the port (+optional address) to listen at")
	flag.Parse()
	debug = *debugptr
	udpaddr, error := net.ResolveUDPAddr(*listen)
	if error != nil {
		fmt.Printf("Cannot parse \"%s\": %s\n", *listen, error)
		os.Exit(1)
	}
	tcpaddr, error := net.ResolveTCPAddr(*listen)
	if error != nil {
		fmt.Printf("Cannot parse \"%s\": %s\n", *listen, error)
		os.Exit(1)
	}
	udpchan := make(chan bool)
	go udpListener(udpaddr, udpchan)
	tcpchan := make(chan bool)
	go tcpListener(tcpaddr, tcpchan)

	<-udpchan // Just to wait the listener, otherwise, the Go runtime ends even if there are live goroutines
	<-tcpchan
}
