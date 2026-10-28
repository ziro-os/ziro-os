package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tarOf(t *testing.T, files map[string]string, extra ...tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for n, c := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(c))
	}
	for _, h := range extra {
		h := h
		tw.WriteHeader(&h)
	}
	tw.Close()
	return b.Bytes()
}

func TestExtractDockerTarStaysInsideTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := extractDockerTar(dir, bytes.NewReader(tarOf(t, map[string]string{"etc/buildkit/buildkitd.toml": "x=1", "../../escape": "no", "/abs": "no"}))); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "etc/buildkit/buildkitd.toml")); string(b) != "x=1" {
		t.Fatalf("file missing: %q", b)
	}
	for _, p := range []string{"escape", "abs"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("%s should have been kept inside the directory: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape")); err == nil {
		t.Fatal("a file escaped the directory")
	}
	for _, h := range []tar.Header{{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, {Name: "h", Typeflag: tar.TypeLink, Linkname: "x"}, {Name: "d", Typeflag: tar.TypeChar}} {
		if err := extractDockerTar(t.TempDir(), bytes.NewReader(tarOf(t, nil, h))); err == nil {
			t.Fatalf("type %v accepted", h.Typeflag)
		}
	}
}

func newBuildAPI(t *testing.T) (*dockerAPI, *[][]string, *httptest.Server) {
	t.Helper()
	var calls [][]string
	d := &dockerAPI{
		run: func(ctx context.Context, args ...string) ([]byte, error) {
			calls = append(calls, args)
			if args[0] == "cp" { // the staged files exist while cp runs
				if _, err := os.Stat(filepath.Join(strings.TrimSuffix(args[2], "/."), "etc/buildkit/buildkitd.toml")); err != nil {
					t.Errorf("cp ran without the staged file: %v", err)
				}
			}
			return nil, nil
		},
		audit: func(actor, action, target string, err error) {},
		runProc: func(ctx context.Context, args []string, in io.Reader, out, errw io.Writer) (int, error) {
			calls = append(calls, args)
			if args[0] == "load" {
				n, _ := io.Copy(io.Discard, in)
				io.WriteString(out, "Loaded image: app:latest\n")
				if n == 0 {
					io.WriteString(errw, "level=fatal msg=empty")
				}
				return 0, nil
			}
			if in != nil {
				b, _ := io.ReadAll(in)
				io.WriteString(out, strings.ToUpper(string(b)))
			}
			io.WriteString(errw, "warn")
			return 3, nil
		},
	}
	srv := httptest.NewServer(d.handler())
	t.Cleanup(srv.Close)
	return d, &calls, srv
}

func TestDockerPutArchiveCopiesIntoTheContainer(t *testing.T) {
	_, calls, srv := newBuildAPI(t)
	req, _ := http.NewRequest("PUT", srv.URL+"/v1.43/containers/buildx_buildkit_default/archive?path=/", bytes.NewReader(tarOf(t, map[string]string{"etc/buildkit/buildkitd.toml": "x"})))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	c := (*calls)[0]
	if c[0] != "cp" || c[1] != "--" || !strings.HasSuffix(c[2], "/.") || c[3] != "buildx_buildkit_default:/" {
		t.Fatalf("cp %q", c)
	}
	for _, q := range []string{"path=etc", "", "path=/a%00b"} {
		req, _ := http.NewRequest("PUT", srv.URL+"/containers/x/archive?"+q, bytes.NewReader(nil))
		if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 400 {
			t.Fatalf("%q: %d", q, resp.StatusCode)
		}
	}
}

func TestDockerExecOverAHijackedConnection(t *testing.T) {
	_, calls, srv := newBuildAPI(t)
	body := `{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["buildctl","dial-stdio"],"Env":["A=b"]}`
	resp, err := http.Post(srv.URL+"/v1.43/containers/buildx_buildkit_default/exec", "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("%v %v", resp, err)
	}
	var cr struct{ Id string }
	json.NewDecoder(resp.Body).Decode(&cr)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := `{"Detach":false,"Tty":false}`
	io.WriteString(conn, "POST /v1.43/exec/"+cr.Id+"/start HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: "+
		string(rune('0'+len(payload)/10))+string(rune('0'+len(payload)%10))+"\r\n\r\n"+payload)
	conn.(*net.TCPConn).CloseWrite() // end of the command's input; the answer must still come
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("status %q", status)
	}
	for l, _ := br.ReadString('\n'); l != "\r\n"; l, _ = br.ReadString('\n') {
	}
	var out, errs string
	for {
		var h [8]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			break
		}
		buf := make([]byte, binary.BigEndian.Uint32(h[4:]))
		io.ReadFull(br, buf)
		if h[0] == 1 {
			out += string(buf)
		} else {
			errs += string(buf)
		}
	}
	if errs != "warn" {
		t.Fatalf("stderr %q stdout %q", errs, out)
	}
	args := (*calls)[0]
	if strings.Join(args, " ") != "exec --interactive --env=A=b -- buildx_buildkit_default buildctl dial-stdio" {
		t.Fatalf("args %q", args)
	}
	ins, err := http.Get(srv.URL + "/exec/" + cr.Id + "/json")
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Running  bool
		ExitCode int
	}
	json.NewDecoder(ins.Body).Decode(&info)
	if info.Running || info.ExitCode != 3 {
		t.Fatalf("inspect %+v", info)
	}
}

func TestDockerExecRefusesWhatItCannotRun(t *testing.T) {
	_, _, srv := newBuildAPI(t)
	for name, body := range map[string]string{
		"no command": `{"Cmd":[]}`, "bad env": `{"Cmd":["x"],"Env":["a b=c"]}`, "bad json": `{`,
	} {
		resp, _ := http.Post(srv.URL+"/containers/x/exec", "application/json", strings.NewReader(body))
		if resp.StatusCode != 400 {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	resp, _ := http.Post(srv.URL+"/containers/-x/exec", "application/json", strings.NewReader(`{"Cmd":["x"]}`))
	if resp.StatusCode != 400 {
		t.Fatalf("an option as a container name: %d", resp.StatusCode)
	}
	r, _ := http.Post(srv.URL+"/containers/x/exec", "application/json", strings.NewReader(`{"Cmd":["x"],"Tty":true}`))
	var cr struct{ Id string }
	json.NewDecoder(r.Body).Decode(&cr)
	resp, _ = http.Post(srv.URL+"/exec/"+cr.Id+"/start", "application/json", strings.NewReader(`{"Tty":true}`))
	if resp.StatusCode != 501 {
		t.Fatalf("tty exec: %d", resp.StatusCode)
	}
	resp, _ = http.Post(srv.URL+"/exec/nope/start", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != 404 {
		t.Fatalf("unknown exec: %d", resp.StatusCode)
	}
}

func TestDockerImageLoadStreamsTheBodyToNerdctl(t *testing.T) {
	_, calls, srv := newBuildAPI(t)
	resp, err := http.Post(srv.URL+"/v1.43/images/load", "application/x-tar", strings.NewReader("tar-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "Loaded image: app:latest") || (*calls)[0][0] != "load" {
		t.Fatalf("%d %q %q", resp.StatusCode, b, *calls)
	}
	resp, _ = http.Post(srv.URL+"/images/load", "application/x-tar", strings.NewReader(""))
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"error"`) {
		t.Fatalf("a failed load is not reported: %q", b)
	}
}

func TestCreateMountsBecomeVolumes(t *testing.T) {
	var b dockerCreateBody
	json.Unmarshal([]byte(`{"Image":"moby/buildkit:buildx-stable-1","HostConfig":{"Privileged":true,"Init":true,"Mounts":[{"Type":"volume","Source":"buildx_buildkit_default_state","Target":"/var/lib/buildkit"},{"Type":"bind","Source":"/etc/x","Target":"/x","ReadOnly":true}]}}`), &b)
	args, err := buildCreateArgs("", "", b)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{"--volume=buildx_buildkit_default_state:/var/lib/buildkit", "--volume=/etc/x:/x:ro", "--privileged", "--init"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q missing from %q", want, got)
		}
	}
	for _, bad := range []string{`{"Type":"tmpfs","Target":"/t"}`, `{"Type":"volume","Source":"","Target":"/t"}`, `{"Type":"volume","Source":"a:b","Target":"/t"}`} {
		var c dockerCreateBody
		json.Unmarshal([]byte(`{"Image":"a","HostConfig":{"Mounts":[`+bad+`]}}`), &c)
		if _, err := buildCreateArgs("", "", c); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
