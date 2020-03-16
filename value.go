package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"net"
	"strings"

	whoisTypes "github.com/webnice/whois/types"
)

// String Return value as string
func (v Value) String() string { return v.source }

// ToLower Return value as string with all Unicode letters mapped to their lower case
func (v Value) ToLower() string { return strings.ToLower(v.source) }

// NameServer Convert value to NameServer struct
func (v Value) NameServer() (ret *whoisTypes.NameServer) {
	var (
		tmp []string
		n   int
	)

	if v.source == "" {
		return
	}
	if tmp = strings.SplitN(v.source, " ", 2); len(tmp) == 0 {
		return
	}
	ret = &whoisTypes.NameServer{
		Name: strings.TrimRight(strings.ToLower(strings.TrimSpace(tmp[0])), "."),
	}
	if len(tmp) < 2 {
		return
	}
	if tmp = strings.Split(tmp[1], ","); len(tmp) == 0 {
		return
	}
	ret.IP = make([]net.IP, 0, len(tmp))
	for n = range tmp {
		ret.IP = append(ret.IP, net.ParseIP(strings.TrimSpace(tmp[n])))
	}

	return
}
