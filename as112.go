/* A name server for the AS112 sink system. See http://www.as112.net/

Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>

*/

package responder

import (
	"regexp"
	"strings"
	"./types"
)

const as112Regexp = "(168\\.192\\.in-addr\\.arpa|154\\.169\\.in-addr\\.arpa|16\\.172\\.in-addr\\.arpa|17\\.172\\.in-addr\\.arpa|18\\.172\\.in-addr\\.arpa|19\\.172\\.in-addr\\.arpa|20\\.172\\.in-addr\\.arpa|21\\.172\\.in-addr\\.arpa|22\\.172\\.in-addr\\.arpa|23\\.172\\.in-addr\\.arpa|24\\.172\\.in-addr\\.arpa|25\\.172\\.in-addr\\.arpa|26\\.172\\.in-addr\\.arpa|27\\.172\\.in-addr\\.arpa|28\\.172\\.in-addr\\.arpa|29\\.172\\.in-addr\\.arpa|30\\.172\\.in-addr\\.arpa|31\\.172\\.in-addr\\.arpa|10\\.in-addr\\.arpa)$"

const defaultTtl = 3600

var (
	as112Domain    = regexp.MustCompile("^" + as112Regexp)
	as112SubDomain = regexp.MustCompile(as112Regexp)
	// Answers to "TXT hostname.as112.net"
	hostnameAnswers = [...]string{
		"Unknown location on Earth.",
		"GRONG, name server written in Go.",
		"See http://as112.net/ for more information.",
	}

	// Name servers of AS112, currently two
	as112nameServers = [...]string{
		"blackhole-1.iana.org",
		"blackhole-2.iana.org",
	}

	hostnamesoa = types.SOArecord{
		Mname: "NOT-CONFIGURED.as112.example.net", // Put the real host name
		Rname: "UNKNOWN.as112.example.net", // Put your email address (with @ replaced by .)
		Serial: 2003030100,
		Refresh: 3600,
		Retry: 600,
		Expire: 2592000,
		Minimum: 15,
	}

	as112soa = types.SOArecord{
		Mname: "prisoner.iana.org",
		Rname: "hostmaster.root-servers.org",
		Serial: 2002040800,
		Refresh: 1800,
		Retry: 900,
		Expire: 604800,
		Minimum: 604800,
	}
)

func nsRecords(domain string) (result []types.RR) {
	result = make([]types.RR, len(as112nameServers))
	for i, text := range as112nameServers {
		result[i].Name = domain
		result[i].Ttl = defaultTtl
		result[i].Tipe = types.NS
		result[i].Class = types.IN
		result[i].Data = types.Encode(text)
	}
	return
}

func soaRecord(domain string, soa types.SOArecord) (result types.RR) {
	result.Name = domain
	result.Ttl = defaultTtl
	result.Tipe = types.SOA
	result.Class = types.IN
	result.Data = types.EncodeSOA(soa)
	return
}

func Respond(query types.DNSquery) (result types.DNSresponse) {
	result.Asection = nil
	qname := strings.ToLower(query.Qname)
	if query.Qclass == types.IN {
		switch {
		case as112Domain.Match(strings.Bytes(qname)):
			result.Responsecode = types.NOERROR
			switch {
			case query.Qtype == types.NS:
				result.Asection = nsRecords(qname)
			case query.Qtype == types.SOA:
				result.Asection = make([]types.RR, 1)
				result.Asection[0] = soaRecord(qname, as112soa)
			case true:
				// Do nothing
			}
		case as112SubDomain.Match(strings.Bytes(qname)):
			result.Responsecode = types.NXDOMAIN
			// TODO: send the proper SOA in the authority section (so we
			// must find which domain matched)
		case qname == "hostname.as112.net":
			result.Responsecode = types.NOERROR
			switch { // TODO: handle ANY qtypes
			case query.Qtype == types.TXT:
				result.Asection = make([]types.RR, len(hostnameAnswers))
				for i, text := range hostnameAnswers {
					result.Asection[i].Name = "hostname.as112.net"
					result.Asection[i].Ttl = defaultTtl
					result.Asection[i].Tipe = types.TXT
					result.Asection[i].Class = types.IN
					result.Asection[i].Data = types.ToTXT(text)
				}
			case query.Qtype == types.NS:
				result.Asection = nsRecords("hostname.as112.net")
			case query.Qtype == types.SOA:
				result.Asection = make([]types.RR, 1)
				result.Asection[0] = soaRecord("hostname.as112.net", hostnamesoa)
			case true:
				// Do nothing
			}
		case true:
			result.Responsecode = types.SERVFAIL
		}
	} else {
		result.Responsecode = types.SERVFAIL
	}
	return result
}
