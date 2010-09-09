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
	"strings"
	"reflect"
	"./responder"
	"./types"
)

const defaultTTL = 3600

var (
	/* Configuration, indexed by keywords, for instance "debug" or
	"servername" */
	globalConfig map[string]interface{}
	debug        int // Not mandatory but it is simpler to use than
	// globalConfig["debug"], which has type interface{}
)

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "%s\n", msg)
	os.Exit(1)
}

// TODO: it would be nice to have a "fatal bool" parameter to indicate
// if we should stop but Go's functions do not have parameters with
// default values :-(
func checkError(msg string, error os.Error) {
	if error != nil {
		fatal(fmt.Sprintf("%s: %s", msg, error))
	}
}

func serialize(packet types.DNSpacket) []byte {
	// TODO: rewrite result as an io.Writer so we can just use Write? See
	// the example in "Effective Go", section "Pointers vs Values"
	result := make([]byte, packet.EdnsBufferSize)
	// ID
	binary.BigEndian.PutUint16(result[0:2], packet.Id)
	// Misc flags...
	result[2] = 0x80 // QR 1 (response), everything else 0
	result[3] = byte(packet.Rcode)
	binary.BigEndian.PutUint16(result[4:6], packet.Qdcount)
	// Ancount
	binary.BigEndian.PutUint16(result[6:8], packet.Ancount)
	// Nscount
	result[8] = 0
	result[9] = 0
	// Arcount
	result[10] = 0
	if packet.Edns {
		result[11] = 1
	} else {
		result[11] = 0
	}
	if len(packet.Qsection) != 1 {
		fatal(fmt.Sprintf("Qsection's length is not 1: %d\n", len(packet.Qsection)))
	}
	encoded_qname := types.Encode(packet.Qsection[0].Qname)
	n := copy(result[12:], encoded_qname)
	if n != len(encoded_qname) {
		fatal(fmt.Sprintf("Copying %d bytes from a name of %d bytes\n",
			n, len(encoded_qname)))
	}
	last := 12 + len(encoded_qname)
	binary.BigEndian.PutUint16(result[last:], packet.Qsection[0].Qtype)
	binary.BigEndian.PutUint16(result[last+2:], packet.Qsection[0].Qclass)
	last = last + 4
	for rrnum, rr := range packet.Ansection {
		encoded_qname := types.Encode(packet.Ansection[rrnum].Name)
		n = copy(result[last:], encoded_qname)
		if n != len(encoded_qname) {
			fatal(fmt.Sprintf("Copying %d bytes from a name of %d bytes\n",
				n, len(encoded_qname)))
		}
		last = last + len(encoded_qname)
		binary.BigEndian.PutUint16(result[last:last+2], rr.Type)
		binary.BigEndian.PutUint16(result[last+2:last+4], rr.Class)
		binary.BigEndian.PutUint32(result[last+4:last+8], rr.TTL)
		binary.BigEndian.PutUint16(result[last+8:last+10], uint16(len(rr.Data)))
		last = last + 10
		n = copy(result[last:], packet.Ansection[rrnum].Data)
		if n != len(packet.Ansection[rrnum].Data) {
			fatal(fmt.Sprintf("Copying %d bytes from data of %d bytes\n",
				n, len(packet.Ansection[rrnum].Data)))
		}
		last = last + len(packet.Ansection[rrnum].Data)
	}
	if packet.Edns {
		result[last] = 0 // EDNS0's Name
		binary.BigEndian.PutUint16(result[last+1:last+3], types.OPT)
		binary.BigEndian.PutUint16(result[last+3:last+5], packet.EdnsBufferSize)
		binary.BigEndian.PutUint32(result[last+5:last+9], 0)
		servernamei, nameexists := globalConfig["servername"]
		if nameexists {
			servername := reflect.NewValue(servernamei).(*reflect.StringValue).Get()
			if packet.Nsid {
				binary.BigEndian.PutUint16(result[last+9:last+11],
					uint16(4+len(servername)))
				binary.BigEndian.PutUint16(result[last+11:last+13], types.NSID)
				binary.BigEndian.PutUint16(result[last+13:last+15], uint16(len(servername)))
				last += 15
				n = copy(result[last:], []byte(servername))
				if n != len(servername) {
					fatal(fmt.Sprintf("Cannot copy servername (length %d bytes), %d bytes actually copied\n", len(servername), n))
				}
				last += int(len(servername))
			} else {
				// Zero EDNS options
				binary.BigEndian.PutUint16(result[last+9:last+11], 0)
				last += 11
			}
		}
	}
	return result[0:last]
}

func readShortInteger(buf *bytes.Buffer) (uint16, bool) {
	slice := make([]byte, 2)
	n, error := buf.Read(slice[0:2])
	if error != nil || n != 2 {
		if debug > 2 {
			fmt.Printf("Error in Read of an int16: %s (%d bytes read)\n", error, n)
		}
		return 0, false
	}
	return binary.BigEndian.Uint16(slice[0:2]), true
}

func readInteger(buf *bytes.Buffer) (uint32, bool) {
	slice := make([]byte, 4)
	n, error := buf.Read(slice[0:4])
	if error != nil || n != 4 {
		if debug > 2 {
			fmt.Printf("Error in Read of an int32: %s (%d bytes read)\n", error, n)
		}
		return 0, false
	}
	return binary.BigEndian.Uint32(slice[0:4]), true
}

func parse(buf *bytes.Buffer) (types.DNSpacket, bool) {
	var (
		packet types.DNSpacket
		ok     bool
	)
	// Initialize with sensible values
	packet.Edns = false
	packet.EdnsBufferSize = 512
	packet.Nsid = false

	packet.Id, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	dnsmisc, ok := readShortInteger(buf)
	if !ok {
		return packet, false
	}
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
	packet.Qdcount, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	if packet.Qdcount != 1 {
		// This may be legal but we would not know what to do with it
		return packet, false
	}
	packet.Ancount, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	// TODO: reject packets with non-empty answer or authority sections
	packet.Nscount, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	packet.Arcount, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	over := false
	labels_max := make([]string, 63)
	labels := labels_max[0:0]
	// Parse the Question section
	nlabels := 0
	for !over {
		labelsize, error := buf.ReadByte()
		if error != nil {
			if error == os.EOF {
				return packet, false
			} else {
				if debug > 2 {
					fmt.Printf("Error in ReadByte: %s\n", error)
				}
				return packet, false
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
				return packet, false
			} else {
				if debug > 2 {
					fmt.Printf("Error in Read %d bytes: %s\n", n, error)
				}
				return packet, false
			}
		}
		nlabels += 1
		labels = labels[0:nlabels]
		labels[nlabels-1] = string(label)
	}
	packet.Qsection = make([]types.Qentry, packet.Qdcount)
	if len(labels) == 0 { // A special case, the root (see issue #4)
		packet.Qsection[0].Qname = "."
	} else {
		packet.Qsection[0].Qname = strings.Join(labels, ".")
	}
	packet.Qsection[0].Qtype, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	packet.Qsection[0].Qclass, ok = readShortInteger(buf)
	if !ok {
		return packet, false
	}
	if packet.Arcount > 0 {
		labelsize, error := buf.ReadByte()
		if error != nil {
			if error == os.EOF {
				return packet, false
			} else {
				if debug > 2 {
					fmt.Printf("Error in ReadByte: %s\n", error)
				}
				return packet, false
			}
		}
		if labelsize != 0 {
			if debug > 2 {
				fmt.Printf("Additional section with non-empty name\n")
			}
			return packet, false
		}
		artype, ok := readShortInteger(buf)
		if !ok {
			return packet, false
		}
		if artype == types.OPT {
			packet.Edns = true
			packet.EdnsBufferSize, ok = readShortInteger(buf)
			if !ok {
				return packet, false
			}
			extrcode, ok := readInteger(buf)
			if !ok {
				return packet, false
			}
			ednslength, ok := readShortInteger(buf)
			if !ok {
				return packet, false
			}
			options := make([]byte, ednslength)
			if ednslength > 0 {
				n, error := buf.Read(options)
				if error != nil || n != int(ednslength) {
					if error == nil {
						// Client left after leaving only a few bytes
						return packet, false
					} else {
						if debug > 2 {
							fmt.Printf("Error in Read %d bytes: %s\n", n, error)
						}
						return packet, false
					}
				}
				over = false
				counter := 0
				for !over {
					optcode := binary.BigEndian.Uint16(options[counter : counter+2])
					if optcode == types.NSID {
						packet.Nsid = true
					}
					optlen := int(binary.BigEndian.Uint16(options[counter+2 : counter+4]))
					if optlen > 0 {
						if counter+4+optlen > len(options) {
							return packet, false
						}
						_ = options[counter+4 : counter+4+optlen] // Yes, useless, I know
					}
					counter += (4 + optlen)
					if counter >= len(options) {
						over = true
					}
					if debug > 3 {
						fmt.Printf("EDNS option code %d\n", optcode)
					}

				}
			}
			if debug > 2 {
				fmt.Printf("EDNS0 found, buffer size is %d, extended rcode is %d, ", packet.EdnsBufferSize, extrcode)
				if ednslength > 0 {
					fmt.Printf("length of options is %d\n", ednslength)
				} else {
					fmt.Printf("no options\n")
				}
			}
		} else {
			// Ignore additional section if not EDNS
		}
	}
	return packet, true
}

func generichandle(buf *bytes.Buffer, remaddr net.Addr) (response types.DNSpacket, noresponse bool) {
	var (
		query           types.DNSquery
		desiredresponse types.DNSresponse
	)
	noresponse = true
	packet, valid := parse(buf)
	if !valid { // Invalid packet or client too impatient
		return
	}
	if debug > 2 {
		fmt.Printf("%s\n", packet)
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
		response.Edns = packet.Edns
		response.Nsid = packet.Nsid
		query.Client = remaddr
		query.Qname = strings.ToLower(packet.Qsection[0].Qname)
		query.Qclass = packet.Qsection[0].Qclass
		query.Qtype = packet.Qsection[0].Qtype
		if packet.Edns {
			query.BufferSize = packet.EdnsBufferSize
			response.EdnsBufferSize = packet.EdnsBufferSize
		} else {
			query.BufferSize = 512 // Traditional value
			response.EdnsBufferSize = 512
		}
		servernamei, nameexists := globalConfig["servername"]
		if query.Qclass == types.CH && query.Qtype == types.TXT &&
			(query.Qname == "hostname.bind" ||
				query.Qname == "id.server") && nameexists {
			servername := reflect.NewValue(servernamei).(*reflect.StringValue).Get()
			desiredresponse.Responsecode = types.NOERROR
			desiredresponse.Ansection = make([]types.RR, 1)
			desiredresponse.Ansection[0] = types.RR{
				Name:  query.Qname,
				TTL:   defaultTTL,
				Type:  types.TXT,
				Class: types.IN,
				Data:  types.ToTXT(servername)}
		} else {
			desiredresponse = responder.Respond(query, globalConfig)
		}
		response.Rcode = desiredresponse.Responsecode
		response.Ancount = uint16(len(desiredresponse.Ansection))
		if response.Ancount > 0 {
			response.Ansection = desiredresponse.Ansection
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
			if debug > 2 {
				fmt.Printf("Error in Write: %s\n", error)
				return
			}
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
		if debug > 2 {
			fmt.Printf("Cannot read message length from TCP connection: %s\n", error)
			return
		}
	}
	msglength := binary.BigEndian.Uint16(smallbuf) // RFC 1035, section 4.2.2 "TCP usage"
	message := make([]byte, msglength)
	n, error = connection.Read(message)
	if error != nil {
		if debug > 2 {
			fmt.Printf("Cannot read message from TCP connection with %s: %s\n", connection.RemoteAddr(), error)
			return
		}
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
			if debug > 2 {
				fmt.Printf("Error in TCP message length Write: %s\n", error)
				return
			}
		}
		n, error = connection.Write(binaryresponse)
		if error != nil {
			if debug > 2 {
				fmt.Printf("Error in TCP message Write: %s\n", error)
				return
			}
		}
	}
	connection.Close() // In theory, we may have other requests. We clearly violate the RFC by not waiting for them. TODO
}

func tcpListener(address *net.TCPAddr, comm chan bool) {
	listener, error := net.ListenTCP("udp", address)
	checkError("Cannot listen", error)
	for {
		connection, error := listener.Accept()
		if error != nil {
			if debug > 1 {
				fmt.Printf("Cannot accept TCP connection: %s\n", error)
				continue
			}
		}
		go tcphandle(connection)
	}
	listener.Close()
	comm <- true
}

func udpListener(address *net.UDPAddr, comm chan bool) {
	listener, error := net.ListenUDP("udp", address)
	checkError("Cannot listen", error)
	for {
		message := make([]byte, 512) // 512 is a reasonable upper limit
		// for *incoming* queries
		n, remaddr, error := listener.ReadFrom(message)
		if error != nil {
			if debug > 1 {
				fmt.Printf("Cannot read UDP from %s: %s\n", remaddr.String(), error)
				continue
			}
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
	nameptr := flag.String("servername", "",
		"Set the server name (and send it to clients)")
	flag.Parse()
	globalConfig = make(map[string]interface{})
	if *nameptr != "" {
		globalConfig["servername"] = *nameptr
	}
	debug = *debugptr
	globalConfig["debug"] = *debugptr
	udpaddr, error := net.ResolveUDPAddr(*listen)
	checkError(fmt.Sprintf("Cannot parse \"%s\": %s\n", *listen), error)
	tcpaddr, error := net.ResolveTCPAddr(*listen)
	checkError(fmt.Sprintf("Cannot parse \"%s\": %s\n", *listen), error)
	udpchan := make(chan bool)
	go udpListener(udpaddr, udpchan)
	tcpchan := make(chan bool)
	go tcpListener(tcpaddr, tcpchan)

	<-udpchan // Just to wait the listener, otherwise, the Go runtime ends
	// even if there are live goroutines
	<-tcpchan
}
