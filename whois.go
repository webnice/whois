package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"strings"
	"time"

	whoisKey "github.com/webnice/whois/key"
)

// New creates a new object and return interface
func New() Interface {
	var w3s = &impl{
		requestTimeout: defaultTimeout,
	}
	return w3s
}

// Errors Ошибки известного состояни, которые могут вернуть функции пакета
func (w3s *impl) Errors() *Error { return Errors() }

// WithTimeout Установка времени ожидания завершения запроса к серверу
func (w3s *impl) WithTimeout(t time.Duration) Interface { w3s.requestTimeout = t; return w3s }

// Source Возвращает ответ whois сервера как есть
func (w3s *impl) Source() []byte { return w3s.domainSrc }

// Parsed Возвращает ответ whois разобранный по сегментам и ключам
func (w3s *impl) Parsed() *Whois { return w3s.domainParsed }

// GetKeyAll Получение всех значений ключа из всех сегментов
func (w3s *impl) GetKeyAll(key whoisKey.Key) (ret []*Value) {
	var n, i int

	for n = range w3s.domainParsed.Segment {
		for i = range w3s.domainParsed.Segment[n] {
			if w3s.domainParsed.Segment[n][i].Key == key {
				ret = append(ret, w3s.domainParsed.Segment[n][i].Value)
			}
		}
	}

	return
}

// Reset object data
func (w3s *impl) Reset() {
	w3s.requestTimeout = defaultTimeout
	w3s.ianaSrc = w3s.ianaSrc[:0]
	w3s.iana = nil
	w3s.domainName = w3s.domainName[:0]
	w3s.domainSrc = w3s.domainSrc[:0]
	w3s.domainParsed = nil
}

func (w3s *impl) cleanDomain(src string) (ret string) {
	const dotKey = `.`

	ret = strings.TrimSpace(src)
	ret = strings.Trim(ret, dotKey)
	ret = strings.ToLower(ret)

	return
}

// Whois Запрос информации о домене или IP адресе
func (w3s *impl) Whois(domain string) (err error) {
	const (
		keyWhois = `whois`
		dotKey   = `.`
		slashKey = `/`
	)
	var (
		whoisSrv   []string
		tmp        []string
		firstLevel string
	)

	if domain = w3s.cleanDomain(domain); domain == "" {
		err = w3s.Errors().IncorrectDomain()
		return
	}
	// Выполнение запроса к whois серверу с лимитированным временем ожидания ответа
	switch w3s.ianaSrc, err = w3s.requestWhois(ianaWhoisServer, defaultWhoisPort, domain); err {
	case nil:
		// Разбор ответа whois сервера на абстрактные блоки данных
		if w3s.iana, err = w3s.parseWhoisSrc(w3s.ianaSrc); err != nil {
			return
		}
		// Извлечение whois сервера содержащего информацию о домене или IP
		if whoisSrv = w3s.getKeyAny(w3s.iana, keyWhois); len(whoisSrv) == 0 {
			err = w3s.Errors().NotFound()
			return
		}
	case w3s.Errors().NotFound():
		// Если сервер не найден и запрос для домена, а не IP, тогда возвращаем как есть - not found
		if w3s.isIP(domain) {
			break
		}
		if tmp = strings.Split(domain, dotKey); len(tmp) > 1 {
			firstLevel = strings.TrimRight(tmp[len(tmp)-1], slashKey)
			whoisSrv = []string{firstLevel + dotKey + tldWhoisServer}
		}
	default:
		return
	}
	if len(whoisSrv) == 0 {
		err = w3s.Errors().NotFound()
		return
	}
	w3s.domainName = domain
	// Загрузка данных
	if w3s.domainSrc, err = w3s.requestWhois(whoisSrv[0], defaultWhoisPort, domain); err != nil {
		return
	}
	// Парсинг данных
	if w3s.domainParsed, err = w3s.parseWhoisSrc(w3s.domainSrc); err != nil {
		return
	}

	return
}
