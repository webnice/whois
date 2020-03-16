package whois

//import "gopkg.in/webnice/debug.v1"
//import "gopkg.in/webnice/log.v2"
import (
	"bytes"
	"net"
	"strings"

	whoisKey "github.com/webnice/whois/key"
)

// Разбор ответа whois сервера на абстрактные блоки данных
func (w3s *impl) parseWhoisSrc(src []byte) (ret *Whois, err error) {
	const (
		blockSeparator = "\n\n"
		comment1       = `>`
		comment2       = `%`
		comment3       = `*`
		comment4       = `#`
	)
	var (
		block   [][]byte
		piece   [][][]byte
		segment []*Segment
		element *Segment
		n, i    int
		key     string
		skeep   bool
	)

	block = bytes.Split(src, []byte(blockSeparator))
	ret = &Whois{
		Segment: make([][]*Segment, 0, len(block)),
	}
	for n = range block {
		if len(block[n]) == 0 {
			continue
		}
		if piece = rexIana.FindAllSubmatch(block[n], -1); len(piece) == 0 && n > 0 {
			continue
		}
		segment = make([]*Segment, 0, len(piece))
		for i = range piece {
			if len(piece[i]) != 3 {
				continue
			}
			element, skeep = new(Segment), false
			element.keySrc = strings.ToLower(strings.TrimSpace(string(piece[i][1])))
			element.Value = &Value{source: strings.TrimSpace(string(piece[i][2]))}
			element.Key = whoisKey.KeyParse(element.keySrc)
			element.Known = element.Key != whoisKey.Unknown
			for _, key = range []string{comment1, comment2, comment3, comment4} {
				if skeep = strings.HasPrefix(element.keySrc, key); skeep {
					break
				}
			}
			if skeep || element.keySrc == "" {
				continue
			}
			segment = append(segment, element)
		}
		if len(segment) == 0 {
			continue
		}
		ret.Segment = append(ret.Segment, segment)
	}
	if len(ret.Segment) == 0 {
		err = w3s.Errors().IanaSrcIncorrect()
		return
	}

	return
}

// Поиск ключа во всех сегментах
func (w3s *impl) getKeyAny(item *Whois, key string) (ret []string) {
	var n, i int

	key = strings.ToLower(key)
	for n = range item.Segment {
		for i = range item.Segment[n] {
			if strings.EqualFold(item.Segment[n][i].keySrc, key) {
				ret = append(ret, item.Segment[n][i].Value.source)
			}
		}
	}

	return
}

// Проверка строки на IP адрес
func (w3s *impl) isIP(src string) (ret bool) {
	var ip = net.ParseIP(src)
	ret = ip.To4() != nil || ip.To16() != nil
	return
}
