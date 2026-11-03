package crypto

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := RandomBytes(32)
	for _, pt := range [][]byte{{}, []byte("hello"), bytes.Repeat([]byte{0}, 65536), []byte("a\x00b\n\"$😀")} {
		aad := SecretAAD("org_a", "prj_b", "env_c", "KEY", 3)
		ct, err := Seal(key, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if ct[0] != 0x01 || len(ct) != 1+12+len(pt)+16 {
			t.Fatalf("unexpected format: len=%d first=%x", len(ct), ct[0])
		}
		got, err := Open(key, ct, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip mismatch")
		}
	}
}

func TestOpenRejectsWrongAADKeyAndTamper(t *testing.T) {
	key := RandomBytes(32)
	ct, _ := Seal(key, []byte("secret"), SecretAAD("o", "p", "e", "K", 1))
	cases := map[string]func() ([]byte, error){
		"other version": func() ([]byte, error) { return Open(key, ct, SecretAAD("o", "p", "e", "K", 2)) },
		"other key":     func() ([]byte, error) { return Open(key, ct, SecretAAD("o", "p", "e", "K2", 1)) },
		"other env":     func() ([]byte, error) { return Open(key, ct, SecretAAD("o", "p", "e2", "K", 1)) },
		"other project": func() ([]byte, error) { return Open(key, ct, SecretAAD("o", "p2", "e", "K", 1)) },
		"other org":     func() ([]byte, error) { return Open(key, ct, SecretAAD("o2", "p", "e", "K", 1)) },
		"change aad":    func() ([]byte, error) { return Open(key, ct, ChangeAAD("o", "p", "e", "K", "1")) },
		"wrong dek":     func() ([]byte, error) { return Open(RandomBytes(32), ct, SecretAAD("o", "p", "e", "K", 1)) },
		"tampered": func() ([]byte, error) {
			c := append([]byte(nil), ct...)
			c[len(c)-1] ^= 1
			return Open(key, c, SecretAAD("o", "p", "e", "K", 1))
		},
		"bad version byte": func() ([]byte, error) {
			c := append([]byte(nil), ct...)
			c[0] = 2
			return Open(key, c, SecretAAD("o", "p", "e", "K", 1))
		},
		"truncated": func() ([]byte, error) { return Open(key, ct[:10], SecretAAD("o", "p", "e", "K", 1)) },
		"empty":     func() ([]byte, error) { return Open(key, nil, SecretAAD("o", "p", "e", "K", 1)) },
	}
	for name, f := range cases {
		pt, err := f()
		if err != ErrDecrypt || pt != nil {
			t.Errorf("%s: expected ErrDecrypt, got %v %q", name, err, pt)
		}
	}
}

func TestAADDistinct(t *testing.T) {
	// "|" separators keep fields from sliding into one another for our ID
	// alphabet (ids and keys never contain "|").
	a := SecretAAD("org_x", "prj_y", "env_z", "K", 1)
	b := SecretAAD("org_x", "prj_y", "env_z", "K", 11)
	if bytes.Equal(a, b) {
		t.Fatal("aad collision")
	}
	if string(DEKAAD("o", "p")) != "coffer/dek/v1|o|p" {
		t.Fatal("dek aad format")
	}
	if string(SecretAAD("o", "p", "e", "K", 12)) != "coffer/secret/v1|o|p|e|K|12" {
		t.Fatal("secret aad format")
	}
	if string(ChangeAAD("o", "p", "e", "K", "chg_1")) != "coffer/change/v1|o|p|e|K|chg_1" {
		t.Fatal("change aad format")
	}
}

func TestTokens(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok := NewToken(PATPrefix)
		if !strings.HasPrefix(tok, "cof_pat_") || !WellFormedToken(tok) || seen[tok] {
			t.Fatalf("bad token %q", tok)
		}
		seen[tok] = true
	}
	st := NewToken(ServicePrefix)
	if !strings.HasPrefix(st, "cof_st_") || !WellFormedToken(st) {
		t.Fatal("bad st")
	}
	for _, bad := range []string{"", "cof_pat_", "cof_pat_abc", "xyz_" + st[7:], st + "A", "cof_pat_" + strings.Repeat("!", 43)} {
		if WellFormedToken(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if len(TokenHash("x")) != 32 {
		t.Fatal("hash len")
	}
}

func TestNewID(t *testing.T) {
	id := NewID("usr")
	if !strings.HasPrefix(id, "usr_") || len(id) != 4+32 || strings.ToLower(id) != id {
		t.Fatalf("bad id %q", id)
	}
}

func TestPasswordHashVerify(t *testing.T) {
	h := NewHasher(19456)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=19456,t=2,p=2$") {
		t.Fatalf("unexpected phc %q", enc)
	}
	if ok, _ := h.Verify(ctx, enc, "correct horse battery"); !ok {
		t.Fatal("verify failed")
	}
	if ok, _ := h.Verify(ctx, enc, "correct horse batterY"); ok {
		t.Fatal("wrong password verified")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=19456,t=2,p=2$AAAA$AAAA", "plain", "$argon2id$v=19$m=1,t=2,p=2$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if ok, _ := h.Verify(ctx, bad, "x"); ok {
			t.Fatalf("malformed hash verified: %q", bad)
		}
	}
	if err := h.VerifyDummy(ctx, "whatever"); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsRehash(t *testing.T) {
	h := NewHasher(19456)
	enc, err := h.Hash(context.Background(), "some-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if h.NeedsRehash(enc) {
		t.Error("fresh hash needs rehash")
	}
	if !NewHasher(19456 * 2).NeedsRehash(enc) {
		t.Error("hash with other memory cost does not need rehash")
	}
	if !h.NeedsRehash("garbage") {
		t.Error("garbage does not need rehash")
	}
}
