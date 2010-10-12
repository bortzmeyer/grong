/* A name server for the AS112 sink system. See http://www.as112.net/

Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>

 Example of use:

 grong -servername "grong.cloud.as112.test" -- -email toto.example.net -hostname me.as112.net -location "In the cloud"

*/

package responder

import (
	"regexp"
	"strings"
	"fmt"
	"os"
	"./types"
	"./myflag"
)

const as112Regexp = "(168\\.192\\.in-addr\\.arpa|154\\.169\\.in-addr\\.arpa|16\\.172\\.in-addr\\.arpa|17\\.172\\.in-addr\\.arpa|18\\.172\\.in-addr\\.arpa|19\\.172\\.in-addr\\.arpa|20\\.172\\.in-addr\\.arpa|21\\.172\\.in-addr\\.arpa|22\\.172\\.in-addr\\.arpa|23\\.172\\.in-addr\\.arpa|24\\.172\\.in-addr\\.arpa|25\\.172\\.in-addr\\.arpa|26\\.172\\.in-addr\\.arpa|27\\.172\\.in-addr\\.arpa|28\\.172\\.in-addr\\.arpa|29\\.172\\.in-addr\\.arpa|30\\.172\\.in-addr\\.arpa|31\\.172\\.in-addr\\.arpa|10\\.in-addr\\.arpa)$"

const defaultTTL = 3600

var (
	as112Domain    = regexp.MustCompile("^" + as112Regexp)
	as112SubDomain = regexp.MustCompile("\\." + as112Regexp)
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
		Mname:   "NOT-CONFIGURED-use-hostname-option.as112.example.net", // Put the real hostname with the -hostname command-line option. We do not use -server which has lightly different semantics.
		Rname:   "UNKNOWN-use-email-option.as112.example.net",           // Put your email address (with @ replaced by .) with the -email command-line option
		Serial:  2003030100,
		Refresh: 3600,
		Retry:   600,
		Expire:  2592000,
		Minimum: 15,
	}

	as112soa = types.SOArecord{
		Mname:   "prisoner.iana.org",
		Rname:   "hostmaster.root-servers.org",
		Serial:  2002040800,
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minimum: 604800,
	}
)

func nsRecords(domain string) (result []types.RR) {
	result = make([]types.RR, len(as112nameServers))
	for i, text := range as112nameServers {
		result[i] = types.RR{
			Name:  domain,
			TTL:   defaultTTL,
			Type:  types.NS,
			Class: types.IN,
			Data:  types.Encode(text),
		}
	}
	return
}

func soaRecord(domain string, soa types.SOArecord) (result types.RR) {
	result = types.RR{
		Name:  domain,
		TTL:   defaultTTL,
		Type:  types.SOA,
		Class: types.IN,
		Data:  types.EncodeSOA(soa),
	}
	return
}

func Respond(query types.DNSquery, config map[string]interface{}) (result types.DNSresponse) {
	result.Ansection = nil
	qname := strings.ToLower(query.Qname)
	if query.Qclass == types.IN {
		switch {
		case as112Domain.Match([]byte(qname)):
			result.Responsecode = types.NOERROR
			switch {
			case query.Qtype == types.NS:
				result.Ansection = nsRecords(query.Qname)
			case query.Qtype == types.SOA:
				result.Ansection = make([]types.RR, 1)
				result.Ansection[0] = soaRecord(query.Qname, as112soa)
			default:
				// Do nothing
			}
		case as112SubDomain.Match([]byte(qname)):
			result.Responsecode = types.NXDOMAIN
			// TODO: send the proper SOA in the authority section (so we
			// must find which domain matched)
		case qname == "hostname.as112.net":
			result.Responsecode = types.NOERROR
			switch query.Qtype { // TODO: handle ANY qtypes
			case types.TXT:
				result.Ansection = make([]types.RR, len(hostnameAnswers))
				for i, text := range hostnameAnswers {
					result.Ansection[i] = types.RR{
						Name:  query.Qname,
						TTL:   defaultTTL,
						Type:  types.TXT,
						Class: types.IN,
						Data:  types.ToTXT(text),
					}
				}
			case types.NS:
				result.Ansection = nsRecords(query.Qname)
			case types.SOA:
				result.Ansection = []types.RR{soaRecord(query.Qname, hostnamesoa)}
			default:
				// Do nothing
			}
		default:
			result.Responsecode = types.SERVFAIL
		}
	} else {
		result.Responsecode = types.SERVFAIL
	}
	return result
}

func Init(firstoption int) {
	flag.Reinit(firstoption)
	helpptr := flag.Bool("help", false, "Displays usage instructions")
	emailptr := flag.String("email", "",
		"Set the email address of the manager for this server (in DNS format, with . instead of @)")
	locationptr := flag.String("location", "",
		"Set the location of this server, for instance \"ALIX exchange point in Somewhere, Somestate\"")
	hostnameptr := flag.String("hostname", "",
		"Set the official host name for this server")
	flag.Parse()
	help := *helpptr
	if help {
		fmt.Printf("Usage of the AS112 responder:\n")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if *emailptr != "" {
		hostnamesoa.Rname = *emailptr
	}
	if *locationptr != "" {
		hostnameAnswers[0] = *locationptr
	}
	if *hostnameptr != "" {
		hostnamesoa.Mname = *hostnameptr
	}
}
