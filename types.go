package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"regexp"
	"time"

	whoisKey "github.com/webnice/whois/key"
)

const (
	ianaWhoisServer  = `whois.iana.org`    // Is an iana whois server
	tldWhoisServer   = `whois-servers.net` // Is an tld whois server
	defaultWhoisPort = uint16(43)          // Is an default whois port
	defaultTimeout   = 30 * time.Second    // Request timeout default limit
)

var (
	rexIana = regexp.MustCompile(`(?mi)^([^\:\%]+)\:(.*)$`)
)

// Interface is an interface of package
type Interface interface {
	// WithTimeout Установка времени ожидания завершения запроса к серверу
	WithTimeout(t time.Duration) Interface

	// Whois Запрос информации о домене или IP адресе
	Whois(domain string) (err error)

	// Source Возвращает ответ whois сервера как есть
	Source() (ret []byte)

	// Parsed Возвращает ответ whois разобранный по сегментам и ключам
	Parsed() (ret *Whois)

	// GetKeyAll Получение всех значений ключа из всех сегментов
	GetKeyAll(key whoisKey.Key) (ret []*Value)

	// Reset object data
	Reset()

	// ERRORS

	// Errors Все ошибки известного состояния, которые могут вернуть функции пакета
	Errors() *Error
}

// impl is an implementation of package
type impl struct {
	requestTimeout time.Duration // Время ожидания выполнения запроса
	ianaSrc        []byte        // Ответ iana whois сервера
	iana           *Whois        // Сегменты ответа whois сервера
	domainName     string        // Исходное доменное имя или IP адрес
	domainSrc      []byte        // Ответ whois сервера
	domainParsed   *Whois        // Сегменты ответа whois сервера
}

// Whois parsed data
type Whois struct {
	Segment [][]*Segment
}

// Segment parsed data
type Segment struct {
	keySrc string       // Key source
	Key    whoisKey.Key // Key
	Value  *Value       // Value data
	Known  bool         // Flag key is known
}

// Значение ключа с возможностью конвертации
type Value struct {
	source string
}
