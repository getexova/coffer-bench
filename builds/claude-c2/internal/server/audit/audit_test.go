package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixed() *Event {
	return &Event{
		Chain: "org_x", Seq: 7, TS: time.Date(2026, 10, 30, 10, 0, 0, 123456789, time.UTC),
		OrgID: "org_x", ActorType: "user", ActorID: "usr_1", Action: "secret.read",
		Target: "web/dev/<DB_URL>&", SourceIP: "127.0.0.1", Result: Success,
		Details:  map[string]any{"version": 3, "via": "export", "b": true, "nested": map[string]any{"z": 1, "a": "x"}},
		PrevHash: GenesisHash,
	}
}

func TestCanonicalGolden(t *testing.T) {
	e := fixed()
	prepare(e, e.TS)
	c, err := Canonical(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"secret.read","actor_id":"usr_1","actor_type":"user","chain":"org_x",` +
		`"details":{"b":true,"nested":{"a":"x","z":1},"version":3,"via":"export"},"org_id":"org_x",` +
		`"prev_hash":"` + GenesisHash + `","result":"success","seq":7,"source_ip":"127.0.0.1",` +
		`"target":"web/dev/<DB_URL>&","ts":"2026-10-30T10:00:00.123456Z"}`
	if string(c) != want {
		t.Fatalf("canonical:\n got %s\nwant %s", c, want)
	}
	h, _ := ComputeHash(e)
	sum := sha256.Sum256([]byte(GenesisHash + want))
	if h != hex.EncodeToString(sum[:]) {
		t.Fatal("hash formula")
	}
}

func TestCanonicalNullOrgAndEmptyDetails(t *testing.T) {
	e := &Event{Chain: PlatformChain, Seq: 1, TS: time.Unix(0, 0), Action: "auth.login", Result: Failed, PrevHash: GenesisHash}
	prepare(e, e.TS)
	c, _ := Canonical(e)
	if !strings.Contains(string(c), `"org_id":null`) || !strings.Contains(string(c), `"details":{}`) || !strings.Contains(string(c), `"ts":"1970-01-01T00:00:00.000000Z"`) {
		t.Fatalf("got %s", c)
	}
}

// Details survive a JSON (jsonb) round trip with an identical hash.
func TestDetailsRoundTripStable(t *testing.T) {
	e := fixed()
	prepare(e, e.TS)
	h1, _ := ComputeHash(e)
	b, _ := json.Marshal(e.Details)
	d, err := decodeDetails(b)
	if err != nil {
		t.Fatal(err)
	}
	e2 := *e
	e2.Details = d
	h2, _ := ComputeHash(&e2)
	if h1 != h2 {
		t.Fatal("hash changed after details round trip")
	}
	// Any change to any field changes the hash.
	for _, mut := range []func(*Event){
		func(x *Event) { x.Target = "other" },
		func(x *Event) { x.Seq++ },
		func(x *Event) { x.Result = Denied },
		func(x *Event) { x.TS = x.TS.Add(time.Microsecond) },
		func(x *Event) { x.Details = map[string]any{"version": json.Number("4")} },
		func(x *Event) { x.PrevHash = strings.Repeat("1", 64) },
		func(x *Event) { x.OrgID = "" },
	} {
		e3 := *e
		mut(&e3)
		if h, _ := ComputeHash(&e3); h == h1 {
			t.Fatal("mutation did not change hash")
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("a\x00b\xffc"); got != "ab�c" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("é", 3000)
	got := Sanitize(long)
	if len(got) > maxField+4 || !strings.HasSuffix(got, "…") {
		t.Fatalf("len %d", len(got))
	}
}
