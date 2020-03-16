package types

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"net"
)

// NameServer Address
type NameServer struct {
	Name string
	IP   []net.IP
}
