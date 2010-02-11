package responder

import (
	"net"
	"./types"
)

func txtRecord(client net.Addr) []byte {
	sclient := client.String()
	return types.ToTXT(sclient)
}

func Respond(query types.DNSquery) types.DNSresponse {
	var (
		result types.DNSresponse
	)
	result.Asection = nil
	switch {
	case query.Qclass != types.IN:
		result.Responsecode = types.SERVFAIL
	case query.Qtype == types.TXT:
		result.Responsecode = types.NOERROR
		ancount := 1
		result.Asection = make([]types.RR, ancount)
		result.Asection[0].Name = query.Qname
		result.Asection[0].Tipe = types.TXT
		result.Asection[0].Class = types.IN
		result.Asection[0].Ttl = 0
		// TODO: better formatting, for instance allowing to have only the IP address
		result.Asection[0].Data = txtRecord(query.Client)
	case query.Qtype == types.ALL:
		result.Responsecode = types.NOERROR
		ancount := 1 // TODO: add an A or a AAAA
		// TODO: reuse the code for the case of QTYPE=TXT
		result.Asection = make([]types.RR, ancount)
		result.Asection[0].Name = query.Qname
		result.Asection[0].Tipe = types.TXT
		result.Asection[0].Class = types.IN
		result.Asection[0].Ttl = 0
		result.Asection[0].Data = txtRecord(query.Client)
		// TODO: handle A and AAAA QTYPEs
	case true:
		result.Responsecode = types.NOERROR
	}
	return result
}

func init() {}
