package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"testing"
)

func TestWhois(t *testing.T) {
	var (
		err      error
		w3s      Interface
		scenario = []string{
			"com",
			"google.com",
			"google.net",
			"google.org",
			"google.mobi",
			"google.cn",
			"google.com.cn",
			"google.in",
			"1.1.1.1",
			"2.1.1.1",
			"3.1.1.1",
			"4.1.1.1",
			"5.1.1.1",
			"8.8.8.8",
			"8.8.4.4",
			"77.88.8.8",
			"77.88.8.1",
			"2001:4860:4860::8888",
			"2001:4860:4860::8844",
		}
	)

	w3s = New()
	for _, v := range scenario {
		w3s.Reset()
		if err = w3s.Whois(v); err != nil {
			t.Fatalf("whois error: %s", err)
			return
		}
		if len(w3s.Source()) == 0 {
			t.Fatalf("whois error, response is nil")
			return
		}
	}
}
