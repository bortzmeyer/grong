package responder

import (
	"./types"
)

func Respond(query types.DNSquery) types.DNSresponse {
	var (
		result types.DNSresponse
	)
	result.Responsecode = types.REFUSED
	return result
}

func init() {}
