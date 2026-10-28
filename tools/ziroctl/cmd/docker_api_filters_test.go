package cmd

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestParseDockerFiltersBothShapes(t *testing.T) {
	for _, raw := range []string{`{"label":{"com.docker.compose.project=p":true,"x":false}}`, `{"label":["com.docker.compose.project=p"]}`} {
		f, err := parseDockerFilters(raw, "label")
		if err != nil || len(f["label"]) != 1 || f["label"][0] != "com.docker.compose.project=p" {
			t.Fatalf("%s: %v %v", raw, f, err)
		}
	}
	for _, bad := range []string{`{`, `{"label":5}`, `{"dangling":{"true":true}}`, `[]`} {
		if _, err := parseDockerFilters(bad, "label"); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	if f, err := parseDockerFilters("", "label"); err != nil || len(f) != 0 {
		t.Fatalf("empty: %v %v", f, err)
	}
}

func TestDockerContainerListFilters(t *testing.T) {
	d := &dockerAPI{audit: func(string, string, string, error) {}, run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("a1\nb2\nc3\n"), nil
		}
		return []byte(`[
 {"Id":"a1","Name":"/p-web-1","State":{"Status":"running","Running":true},"Config":{"Image":"nginx","Labels":{"com.docker.compose.project":"p","com.docker.compose.service":"web","com.docker.compose.oneoff":"False"}},"NetworkSettings":{"Networks":{"p_default":{}}}},
 {"Id":"b2","Name":"/q-db-1","State":{"Status":"exited","Running":false},"Config":{"Image":"pg","Labels":{"com.docker.compose.project":"q"}},"NetworkSettings":{"Networks":{}}},
 {"Id":"c3","Name":"/other","State":{"Status":"running","Running":true},"Config":{"Image":"nginx"},"NetworkSettings":{"Networks":{}}}]`), nil
	}}
	h := d.handler()
	names := func(filters string) string {
		r := do(h, "GET", "/containers/json?all=1&filters="+url.QueryEscape(filters))
		if r.Code != 200 {
			return r.Body.String()
		}
		var l []struct{ Names []string }
		json.Unmarshal(r.Body.Bytes(), &l)
		var out []string
		for _, c := range l {
			out = append(out, c.Names[0])
		}
		return strings.Join(out, ",")
	}
	for filters, want := range map[string]string{
		``: "/p-web-1,/q-db-1,/other",
		`{"label":{"com.docker.compose.project=p":true}}`:                                      "/p-web-1",
		`{"label":["com.docker.compose.project=p","com.docker.compose.service=web"]}`:          "/p-web-1",
		`{"label":{"com.docker.compose.project=p":true,"com.docker.compose.service=db":true}}`: "",
		`{"label":{"com.docker.compose.project":true}}`:                                        "/p-web-1,/q-db-1",
		`{"status":{"exited":true}}`:                                                           "/q-db-1",
		`{"name":{"^/p-":true}}`:                                                               "/p-web-1",
		`{"id":{"c":true}}`:                                                                    "/other",
		`{"ancestor":{"pg":true}}`:                                                             "/q-db-1",
		`{"network":{"p_default":true}}`:                                                       "/p-web-1",
	} {
		if got := names(filters); got != want {
			t.Errorf("%s: got %q want %q", filters, got, want)
		}
	}
	if r := do(h, "GET", "/containers/json?filters="+url.QueryEscape(`{"health":{"healthy":true}}`)); r.Code != 400 || !strings.Contains(r.Body.String(), "unsupported filter") {
		t.Fatalf("unknown filter: %d %s", r.Code, r.Body.String())
	}
}

func TestDockerNetworkAndVolumeFilters(t *testing.T) {
	d := &dockerAPI{audit: func(string, string, string, error) {}, run: func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] + " " + args[1] {
		case "network ls":
			return []byte("bridge\np_default\n"), nil
		case "network inspect":
			return []byte(`[{"Name":"bridge","Id":"1"},{"Name":"p_default","Id":"2","Labels":{"com.docker.compose.project":"p"}}]`), nil
		case "volume ls":
			return []byte("p_data\nother\n"), nil
		case "volume inspect":
			return []byte(`[{"Name":"p_data","Labels":{"com.docker.compose.project":"p"}},{"Name":"other"}]`), nil
		}
		return nil, nil
	}}
	h := d.handler()
	f := url.QueryEscape(`{"label":{"com.docker.compose.project=p":true}}`)
	var nets []struct{ Name string }
	json.Unmarshal(do(h, "GET", "/networks?filters="+f).Body.Bytes(), &nets)
	if len(nets) != 1 || nets[0].Name != "p_default" {
		t.Fatalf("networks %+v", nets)
	}
	var vols struct{ Volumes []struct{ Name string } }
	json.Unmarshal(do(h, "GET", "/volumes?filters="+f).Body.Bytes(), &vols)
	if len(vols.Volumes) != 1 || vols.Volumes[0].Name != "p_data" {
		t.Fatalf("volumes %+v", vols)
	}
	if r := do(h, "GET", "/networks?filters="+url.QueryEscape(`{"scope":{"local":true}}`)); r.Code != 400 {
		t.Fatalf("unknown network filter: %d", r.Code)
	}
}
