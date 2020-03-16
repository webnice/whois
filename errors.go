package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"

// Все ошибки определены как константы
const (
	cIncorrectDomain  = "Incorrect domain name or ip address"
	cIanaSrcIncorrect = "The data received from the iana server is incorrect"
	cNotFound         = "Not found"
	cEmptyResponse    = "The server returned an invalid empty response"
)

// Константы указаны в объектах, адрес которых фиксирован всё время работы приложения
// Ошибку с ошибкой можно сравнивать по телу, по адресу и т.п.
var (
	errSingleton        = &Error{}
	errIncorrectDomain  = err(cIncorrectDomain)
	errIanaSrcIncorrect = err(cIanaSrcIncorrect)
	errNotFound         = err(cNotFound)
	errEmptyResponse    = err(cEmptyResponse)
)

type (
	// Error object of package
	Error struct{}
	err   string
)

// Error The error built-in interface implementation
func (e err) Error() string { return string(e) }

// Errors Все ошибки известного состояния, которые могут вернуть функции пакета
func Errors() *Error { return errSingleton }

// ERRORS:

// IncorrectDomain Incorrect domain name or ip address
func (e *Error) IncorrectDomain() error { return &errIncorrectDomain }

// IanaSrcIncorrect The data received from the iana server is incorrect
func (e *Error) IanaSrcIncorrect() error { return &errIanaSrcIncorrect }

// NotFound Not found
func (e *Error) NotFound() error { return &errNotFound }

// EmptyResponse The server returned an invalid empty response
func (e *Error) EmptyResponse() error { return &errEmptyResponse }
