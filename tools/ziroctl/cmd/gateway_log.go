package cmd

import (
	"bufio"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ---- access log ----
//
// One JSON object per line. Requests only append to a pooled buffer and hand it to a single
// writer goroutine through a bounded queue; when the queue is full the line is dropped and
// counted (zirogate_log_dropped_total), so a slow disk can never stall traffic.

const accessLogQueue = 8192

var logBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 512); return &b }}

type accessLog struct {
	ch      chan *[]byte
	dropped *atomic.Uint64
	wg      sync.WaitGroup
}

func newAccessLog(w io.Writer, dropped *atomic.Uint64) *accessLog {
	l := &accessLog{ch: make(chan *[]byte, accessLogQueue), dropped: dropped}
	l.wg.Add(1)
	go l.run(bufio.NewWriterSize(w, 64<<10))
	return l
}

func (l *accessLog) run(bw *bufio.Writer) {
	defer l.wg.Done()
	for line := range l.ch {
		_, _ = bw.Write(*line)
		*line = (*line)[:0]
		logBufPool.Put(line)
		if len(l.ch) == 0 { // idle: do not hold lines back
			_ = bw.Flush()
		}
	}
	_ = bw.Flush()
}

// write queues a finished line (which must end in a newline); it never blocks.
func (l *accessLog) write(line *[]byte) {
	select {
	case l.ch <- line:
	default:
		l.dropped.Add(1)
		*line = (*line)[:0]
		logBufPool.Put(line)
	}
}

// close flushes the queue and stops the writer. Nothing may call write afterwards.
func (l *accessLog) close() {
	close(l.ch)
	l.wg.Wait()
}

// gwAccessRecord is one request's log fields.
type gwAccessRecord struct {
	start        time.Time
	client, host string
	method, path string
	status       int
	bytes        int64
	ms           int64
	upstream     string
	upStatus     int
	upMS         int64
	route        string
	requestID    string
	userAgent    string
	tls          string
	waf          string
}

const logMaxField = 256 // longest request-controlled value logged

func (r *gwAccessRecord) appendJSON(b []byte) []byte {
	b = append(b, `{"ts":"`...)
	b = r.start.UTC().AppendFormat(b, time.RFC3339Nano)
	b = append(b, `","client":`...)
	b = appendJSONString(b, r.client)
	b = append(b, `,"host":`...)
	b = appendJSONString(b, r.host)
	b = append(b, `,"method":`...)
	b = appendJSONString(b, r.method)
	b = append(b, `,"path":`...)
	b = appendJSONString(b, gwTruncate(r.path, logMaxField))
	b = append(b, `,"status":`...)
	b = strconv.AppendInt(b, int64(r.status), 10)
	b = append(b, `,"bytes":`...)
	b = strconv.AppendInt(b, r.bytes, 10)
	b = append(b, `,"ms":`...)
	b = strconv.AppendInt(b, r.ms, 10)
	b = append(b, `,"upstream":`...)
	b = appendJSONString(b, r.upstream)
	if r.upStatus != 0 {
		b = append(b, `,"upstream_status":`...)
		b = strconv.AppendInt(b, int64(r.upStatus), 10)
		b = append(b, `,"upstream_ms":`...)
		b = strconv.AppendInt(b, r.upMS, 10)
	}
	b = append(b, `,"route":`...)
	b = appendJSONString(b, r.route)
	b = append(b, `,"request_id":`...)
	b = appendJSONString(b, r.requestID)
	if r.userAgent != "" {
		b = append(b, `,"user_agent":`...)
		b = appendJSONString(b, gwTruncate(r.userAgent, logMaxField))
	}
	if r.tls != "" {
		b = append(b, `,"tls":`...)
		b = appendJSONString(b, r.tls)
	}
	if r.waf != "" {
		b = append(b, `,"waf":`...)
		b = appendJSONString(b, r.waf)
	}
	return append(b, '}', '\n')
}

func gwTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) { // do not cut a character in half
		n--
	}
	return s[:n]
}

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string. Control characters and invalid UTF-8 are escaped,
// so a hostile request cannot forge or break log lines.
func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b = append(b, '\\', c)
			case c == '\n':
				b = append(b, '\\', 'n')
			case c == '\r':
				b = append(b, '\\', 'r')
			case c == '\t':
				b = append(b, '\\', 't')
			case c < 0x20 || c == 0x7f:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			default:
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, `�`...)
		} else {
			b = append(b, s[i:i+size]...)
		}
		i += size
	}
	return append(b, '"')
}
