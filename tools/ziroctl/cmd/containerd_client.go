package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// A minimal containerd client: the calls `docker network connect` and the health checks need (containers
// List, Get and Update, tasks Get), as gRPC unary calls over HTTP/2 on containerd's unix socket. The official client
// pulls in gRPC, protobuf and OpenTelemetry (about 9 MB in ziroctl) for what is here a few hundred
// bytes of protobuf; the messages are encoded by hand from containerd's API definitions
// (api/services/containers/v1/containers.proto, api/services/tasks/v1/tasks.proto,
// api/types/task/task.proto, v2.2.1). An update names only the fields it changes in its update mask,
// so containerd keeps everything else as it is.

// ctrdContainer is containerd.services.containers.v1.Container, with the fields used here decoded.
type ctrdContainer struct {
	ID       string
	Labels   map[string]string
	SpecType string // google.protobuf.Any type_url
	Spec     []byte // google.protobuf.Any value: the OCI spec as JSON
}

// ctrdTask is the part of containerd.v1.types.Process used here.
type ctrdTask struct {
	Pid    uint32
	Status int // 1 created, 2 running, 3 stopped, 4 paused, 5 pausing
}

const ctrdTaskRunning = 2

type ctrdClient struct {
	http      *http.Client
	namespace string
}

func newCtrdClient(socket, namespace string) *ctrdClient {
	// HTTP/2 without TLS and without an upgrade (prior knowledge), as gRPC speaks on a unix socket.
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: &protos,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &ctrdClient{http: &http.Client{Transport: tr, Timeout: 30 * time.Second}, namespace: namespace}
}

// ctrdError is a gRPC error status from containerd (5 is NOT_FOUND).
type ctrdError struct {
	Code    int
	Message string
}

func (e *ctrdError) Error() string { return e.Message }

func isCtrdNotFound(err error) bool {
	var ce *ctrdError
	return errors.As(err, &ce) && ce.Code == 5
}

// call makes one gRPC unary call and returns the response message.
func (c *ctrdClient) call(ctx context.Context, method string, req []byte) ([]byte, error) {
	body := make([]byte, 5+len(req))
	binary.BigEndian.PutUint32(body[1:5], uint32(len(req)))
	copy(body[5:], req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://containerd"+method, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("Te", "trailers")
	hr.Header.Set("Containerd-Namespace", c.namespace)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("containerd: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("containerd: %v", err)
	}
	status := resp.Trailer.Get("Grpc-Status")
	msg := resp.Trailer.Get("Grpc-Message")
	if status == "" { // a trailers-only response puts the status in the headers
		status, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("containerd: HTTP %d", resp.StatusCode)
	}
	if status != "" && status != "0" {
		code, _ := strconv.Atoi(status)
		if m, err := url.PathUnescape(msg); err == nil {
			msg = m
		}
		return nil, &ctrdError{Code: code, Message: "containerd: " + msg}
	}
	if len(data) < 5 {
		return nil, nil
	}
	if data[0] != 0 {
		return nil, errors.New("containerd: compressed responses are not supported")
	}
	n := binary.BigEndian.Uint32(data[1:5])
	if int(n) > len(data)-5 {
		return nil, errors.New("containerd: short response")
	}
	return data[5 : 5+n], nil
}

func (c *ctrdClient) Containers(ctx context.Context, filters ...string) ([]ctrdContainer, error) {
	var req pbBuf
	for _, f := range filters {
		req.str(1, f)
	}
	out, err := c.call(ctx, "/containerd.services.containers.v1.Containers/List", req.b)
	if err != nil {
		return nil, err
	}
	var list []ctrdContainer
	err = pbEach(out, func(num int, v []byte) error {
		if num == 1 {
			ct, err := decodeCtrdContainer(v)
			if err != nil {
				return err
			}
			list = append(list, ct)
		}
		return nil
	})
	return list, err
}

func (c *ctrdClient) Container(ctx context.Context, id string) (ctrdContainer, error) {
	var req pbBuf
	req.str(1, id)
	out, err := c.call(ctx, "/containerd.services.containers.v1.Containers/Get", req.b)
	if err != nil {
		return ctrdContainer{}, err
	}
	var ct ctrdContainer
	found := false
	err = pbEach(out, func(num int, v []byte) error {
		if num == 1 {
			found = true
			ct, err = decodeCtrdContainer(v)
		}
		return err
	})
	if err == nil && !found {
		err = &ctrdError{Code: 5, Message: "containerd: no container " + id}
	}
	return ct, err
}

// UpdateLabelAndSpec sets one label and replaces the spec, leaving everything else as it is (the
// update mask names only "labels.<key>" and "spec"). A nil spec leaves the spec alone.
func (c *ctrdClient) UpdateLabelAndSpec(ctx context.Context, id, key, value, specType string, spec []byte) error {
	var labels, entry, anyv, ct, mask, req pbBuf
	entry.str(1, key)
	entry.str(2, value)
	labels.msg(2, entry.b)
	ct.str(1, id)
	ct.b = append(ct.b, labels.b...)
	mask.str(1, "labels."+key)
	if spec != nil {
		anyv.str(1, specType)
		anyv.bytes(2, spec)
		ct.msg(5, anyv.b)
		mask.str(1, "spec")
	}
	req.msg(1, ct.b)
	req.msg(2, mask.b)
	_, err := c.call(ctx, "/containerd.services.containers.v1.Containers/Update", req.b)
	return err
}

// UpdateLabel sets one label of a container.
func (c *ctrdClient) UpdateLabel(ctx context.Context, id, key, value string) error {
	return c.UpdateLabelAndSpec(ctx, id, key, value, "", nil)
}

// Task returns the task of a container; a container without one gives a NOT_FOUND error.
func (c *ctrdClient) Task(ctx context.Context, id string) (ctrdTask, error) {
	var req pbBuf
	req.str(1, id)
	out, err := c.call(ctx, "/containerd.services.tasks.v1.Tasks/Get", req.b)
	if err != nil {
		return ctrdTask{}, err
	}
	var t ctrdTask
	err = pbEach(out, func(num int, v []byte) error {
		if num != 1 {
			return nil
		}
		return pbEachRaw(v, func(num int, wire int, val uint64, _ []byte) error {
			switch {
			case num == 3 && wire == 0:
				t.Pid = uint32(val)
			case num == 4 && wire == 0:
				t.Status = int(val)
			}
			return nil
		})
	})
	return t, err
}

func decodeCtrdContainer(b []byte) (ctrdContainer, error) {
	ct := ctrdContainer{Labels: map[string]string{}}
	err := pbEach(b, func(num int, v []byte) error {
		switch num {
		case 1:
			ct.ID = string(v)
		case 2:
			var k, val string
			if err := pbEach(v, func(n int, x []byte) error {
				switch n {
				case 1:
					k = string(x)
				case 2:
					val = string(x)
				}
				return nil
			}); err != nil {
				return err
			}
			ct.Labels[k] = val
		case 5:
			return pbEach(v, func(n int, x []byte) error {
				switch n {
				case 1:
					ct.SpecType = string(x)
				case 2:
					ct.Spec = append([]byte(nil), x...)
				}
				return nil
			})
		}
		return nil
	})
	return ct, err
}

// --- protobuf wire format (https://protobuf.dev/programming-guides/encoding/) ---

type pbBuf struct{ b []byte }

func (p *pbBuf) tag(num, wire int) { p.b = binary.AppendUvarint(p.b, uint64(num)<<3|uint64(wire)) }
func (p *pbBuf) bytes(num int, v []byte) {
	p.tag(num, 2)
	p.b = binary.AppendUvarint(p.b, uint64(len(v)))
	p.b = append(p.b, v...)
}
func (p *pbBuf) str(num int, v string) { p.bytes(num, []byte(v)) }
func (p *pbBuf) msg(num int, v []byte) { p.bytes(num, v) }

// pbEachRaw walks the fields of a message: varints come as val, length-delimited fields as data.
func pbEachRaw(b []byte, fn func(num, wire int, val uint64, data []byte) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errors.New("protobuf: bad tag")
		}
		b = b[n:]
		num, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errors.New("protobuf: bad varint")
			}
			b = b[n:]
			if err := fn(num, wire, v, nil); err != nil {
				return err
			}
		case 1:
			if len(b) < 8 {
				return errors.New("protobuf: short fixed64")
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return errors.New("protobuf: short fixed32")
			}
			b = b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return errors.New("protobuf: bad length")
			}
			data := b[n : n+int(l)]
			b = b[n+int(l):]
			if err := fn(num, wire, 0, data); err != nil {
				return err
			}
		default:
			return fmt.Errorf("protobuf: wire type %d", wire)
		}
	}
	return nil
}

// pbEach walks the length-delimited fields of a message (strings, bytes, messages, map entries).
func pbEach(b []byte, fn func(num int, v []byte) error) error {
	return pbEachRaw(b, func(num, wire int, _ uint64, data []byte) error {
		if wire == 2 {
			return fn(num, data)
		}
		return nil
	})
}

// ctrdLabelFilter is a containerd filter for one label value (filters are "labels.\"k\"==v").
func ctrdLabelFilter(key, value string) string {
	return `labels.` + strconv.Quote(key) + `==` + strconv.Quote(value)
}
