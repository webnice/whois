package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
)

// Выполнение запроса к whois серверу с лимитированным временем ожидания ответа
func (w3s *impl) requestWhois(server string, port uint16, domain string) (ret []byte, err error) {
	const (
		arinSrv       = `whois.arin.net`
		arinFlag      = `n + `
		tcp           = `tcp`
		requestData   = "%s\r\n"
		dialError     = `connect to whois server, error: %s`
		deadlineError = `set deadline for request, error: %s`
		sendingError  = `sending request data to whois server, error: %s`
		readingError  = `reading response data from whois server, error: %s`
		notfound      = `returned 0 objects`
	)
	var (
		address string
		con     net.Conn
	)

	if strings.EqualFold(server, arinSrv) && w3s.isIP(domain) {
		domain = arinFlag + domain
	}
	address = net.JoinHostPort(server, strconv.FormatUint(uint64(port), 10))
	if con, err = net.DialTimeout(tcp, address, w3s.requestTimeout); err != nil {
		err = fmt.Errorf(dialError, err)
		return
	}
	defer func() { _ = con.Close() }()
	// Установка времени ожидания выполнения запроса
	if err = con.SetDeadline(time.Now().Add(w3s.requestTimeout)); err != nil {
		err = fmt.Errorf(deadlineError, err)
		return
	}
	// Отправка запроса на сервер
	if _, err = fmt.Fprintf(con, requestData, domain); err != nil {
		err = fmt.Errorf(sendingError, err)
		return
	}
	// Загрузка ответа сервера
	if ret, err = ioutil.ReadAll(con); err != nil {
		err = fmt.Errorf(readingError, err)
		return
	}
	// Проверка на пустой результат
	if len(ret) == 0 {
		err = w3s.Errors().EmptyResponse()
		return
	}
	// Проверка на не верный домен или не верный IP
	if bytes.Contains(ret, []byte(notfound)) {
		err = w3s.Errors().NotFound()
		return
	}

	return
}
