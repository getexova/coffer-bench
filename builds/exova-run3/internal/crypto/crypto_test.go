package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// testKey returns a deterministic key for tests.
func testKey(t *testing.T, b byte) Key {
	t.Helper()
	var k Key
	for i := range k {
		k[i] = b
	}
	return k
}

// TestAADEncodingIsLengthPrefixed pins the frozen encoding (docs/CONTRACTS.md §5): for each part,
// uvarint(len(part)) followed by its bytes.
func TestAADEncodingIsLengthPrefixed(t *testing.T) {
	got := AAD("coffer:v1", "org1", "proj1", "env1", "API_KEY", "3")

	want := []byte{
		9, 'c', 'o', 'f', 'f', 'e', 'r', ':', 'v', '1',
		4, 'o', 'r', 'g', '1',
		5, 'p', 'r', 'o', 'j', '1',
		4, 'e', 'n', 'v', '1',
		7, 'A', 'P', 'I', '_', 'K', 'E', 'Y',
		1, '3',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD encoding mismatch\n got: %v\nwant: %v", got, want)
	}
}

// TestAADLengthPrefixesStopFieldShifting is the security property behind the length prefixes.
//
// Without them, concatenating parts would make ("a","bc") and ("ab","c") produce identical bytes,
// and a value could be shifted across a field boundary to forge a valid tag. The test states that
// case explicitly, and then checks it through the real AAD builders for every field pair that a
// forged ciphertext would need to move across.
func TestAADLengthPrefixesStopFieldShifting(t *testing.T) {
	if bytes.Equal(AAD("a", "bc"), AAD("ab", "c")) {
		t.Fatal("AAD is ambiguous: a value can be shifted across a field boundary")
	}

	cases := []struct {
		name  string
		left  []byte
		right []byte
	}{
		{
			name:  "organization shifted into project",
			left:  SecretAAD("org", "1proj", "env", "KEY", 1),
			right: SecretAAD("org1", "proj", "env", "KEY", 1),
		},
		{
			name:  "project shifted into environment",
			left:  SecretAAD("org", "proj", "1env", "KEY", 1),
			right: SecretAAD("org", "proj1", "env", "KEY", 1),
		},
		{
			name:  "key shifted into version",
			left:  SecretAAD("org", "proj", "env", "KEY1", 1),
			right: SecretAAD("org", "proj", "env", "KEY", 11),
		},
		{
			name:  "domain swapped",
			left:  SecretAAD("org", "proj", "env", "KEY", 1),
			right: ChangeAAD("org", "proj", "env", "KEY", "1"),
		},
	}
	for _, tc := range cases {
		if bytes.Equal(tc.left, tc.right) {
			t.Errorf("%s: two different coordinates produced the same associated data", tc.name)
		}
	}
}

// TestAADFieldsAreUnambiguousForEverySplit is an exhaustive check over short parts: for every way of
// splitting one string into two parts, the encoding must differ from every other split.
func TestAADFieldsAreUnambiguousForEverySplit(t *testing.T) {
	const s = "abcd"
	seen := make(map[string][2]string, len(s)+1)
	for i := 0; i <= len(s); i++ {
		pair := [2]string{s[:i], s[i:]}
		enc := string(AAD(pair[0], pair[1]))
		if prev, ok := seen[enc]; ok {
			t.Fatalf("splits %v and %v encode identically", prev, pair)
		}
		seen[enc] = pair
	}
}

// TestSecretAADIncludesEveryCoordinate checks each field actually participates in the tag.
func TestSecretAADIncludesEveryCoordinate(t *testing.T) {
	base := SecretAAD("org", "proj", "env", "KEY", 1)
	variants := map[string][]byte{
		"org":     SecretAAD("org2", "proj", "env", "KEY", 1),
		"project": SecretAAD("org", "proj2", "env", "KEY", 1),
		"env":     SecretAAD("org", "proj", "env2", "KEY", 1),
		"key":     SecretAAD("org", "proj", "env", "KEY2", 1),
		"version": SecretAAD("org", "proj", "env", "KEY", 2),
	}
	for field, v := range variants {
		if bytes.Equal(base, v) {
			t.Errorf("changing %s did not change the associated data", field)
		}
	}
}

// TestSealOpenRoundTrip covers exact round-tripping, including the empty value, which is valid
// (SPEC §3: "0 to 65,536 bytes inclusive") and must not be confused with a tombstone.
func TestSealOpenRoundTrip(t *testing.T) {
	k := testKey(t, 7)
	aad := SecretAAD("org", "proj", "env", "API_KEY", 1)

	values := [][]byte{
		{},
		[]byte("x"),
		[]byte("line1\nline2\r\n"),
		[]byte("quote\" back\\slash $dollar"),
		[]byte(strings.Repeat("a", 65536)),
		{0x00, 0x01, 0xff},
	}
	for _, want := range values {
		nonce, ct, err := Seal(k, want, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if len(nonce) != NonceSize {
			t.Fatalf("nonce length %d, want %d", len(nonce), NonceSize)
		}
		if len(ct) != len(want)+TagSize {
			t.Fatalf("ciphertext length %d, want %d", len(ct), len(want)+TagSize)
		}
		got, err := Open(k, nonce, ct, aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch: got %q want %q", got, want)
		}
	}
}

// TestNoncesAreUnique guards against a fixed nonce, which would be a catastrophic GCM failure: two
// messages under one key and one nonce leak their XOR and destroy authenticity.
func TestNoncesAreUnique(t *testing.T) {
	k := testKey(t, 3)
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		nonce, _, err := Seal(k, []byte("same plaintext"), nil)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if seen[string(nonce)] {
			t.Fatal("a nonce repeated")
		}
		seen[string(nonce)] = true
	}
}

// TestCopiedCiphertextNeverReturnsAValue is the required AAD copy-failure test.
//
// A ciphertext is sealed for one row and then opened as every other row it could be copied into.
// Every attempt must fail with ErrDecrypt and must return no plaintext at all — not a partial
// value, not a zero-length value, and not an error that carries the value.
func TestCopiedCiphertextNeverReturnsAValue(t *testing.T) {
	k := testKey(t, 11)
	const secret = "postgres://user:hunter2@db.internal/prod"

	original := SecretAAD("org-1", "proj-1", "env-1", "DATABASE_URL", 3)
	nonce, ct, err := Seal(k, []byte(secret), original)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	copies := map[string][]byte{
		"another organization": SecretAAD("org-2", "proj-1", "env-1", "DATABASE_URL", 3),
		"another project":      SecretAAD("org-1", "proj-2", "env-1", "DATABASE_URL", 3),
		"another environment":  SecretAAD("org-1", "proj-1", "env-2", "DATABASE_URL", 3),
		"another key":          SecretAAD("org-1", "proj-1", "env-1", "OTHER_KEY", 3),
		"another version":      SecretAAD("org-1", "proj-1", "env-1", "DATABASE_URL", 4),
		"the change domain":    ChangeAAD("org-1", "proj-1", "env-1", "DATABASE_URL", "chg-1"),
		"no associated data":   nil,
	}
	for name, aad := range copies {
		got, err := Open(k, nonce, ct, aad)
		if err == nil {
			t.Fatalf("%s: a copied ciphertext decrypted (returned %q)", name, got)
		}
		if err != ErrDecrypt {
			t.Fatalf("%s: error %v, want ErrDecrypt", name, err)
		}
		if got != nil {
			t.Fatalf("%s: a failed open returned %q, want no value at all", name, got)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: the error carries the plaintext", name)
		}
	}
}

// TestOpenRejectsMalformedInput covers the shapes that must fail closed rather than panic.
func TestOpenRejectsMalformedInput(t *testing.T) {
	k := testKey(t, 5)
	nonce, ct, err := Seal(k, []byte("v"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := map[string]struct{ nonce, ct []byte }{
		"short nonce":      {nonce[:11], ct},
		"long nonce":       {append(append([]byte{}, nonce...), 0), ct},
		"nil nonce":        {nil, ct},
		"truncated tag":    {nonce, ct[:TagSize-1]},
		"empty ciphertext": {nonce, nil},
		"flipped tag bit":  {nonce, flipLast(ct)},
		"flipped body bit": {nonce, flipFirst(ct)},
	}
	for name, tc := range cases {
		got, err := Open(k, tc.nonce, tc.ct, nil)
		if err == nil || got != nil {
			t.Fatalf("%s: Open returned (%q, %v), want (nil, error)", name, got, err)
		}
	}
}

func flipLast(b []byte) []byte {
	out := append([]byte{}, b...)
	out[len(out)-1] ^= 0x01
	return out
}

func flipFirst(b []byte) []byte {
	out := append([]byte{}, b...)
	out[0] ^= 0x01
	return out
}

// TestWrongKeyFails checks that a different data key cannot open the ciphertext.
func TestWrongKeyFails(t *testing.T) {
	nonce, ct, err := Seal(testKey(t, 1), []byte("v"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got, err := Open(testKey(t, 2), nonce, ct, nil); err == nil || got != nil {
		t.Fatalf("a different key opened the ciphertext: %q", got)
	}
}

// TestDataKeyWrapUnwrap covers the envelope: a data key wrapped for one project cannot be unwrapped
// as another project's key, and cannot be unwrapped with a different master key.
func TestDataKeyWrapUnwrap(t *testing.T) {
	master := testKey(t, 21)
	dek := testKey(t, 22)
	aad := DataKeyAAD("org-1", "proj-1", 1)

	nonce, wrapped, err := WrapDataKey(master, dek, aad)
	if err != nil {
		t.Fatalf("WrapDataKey: %v", err)
	}
	if bytes.Contains(wrapped, dek[:]) {
		t.Fatal("the wrapped key contains the plaintext data key")
	}

	got, err := UnwrapDataKey(master, nonce, wrapped, aad)
	if err != nil {
		t.Fatalf("UnwrapDataKey: %v", err)
	}
	if got != dek {
		t.Fatal("unwrapped data key differs from the original")
	}

	if _, err := UnwrapDataKey(master, nonce, wrapped, DataKeyAAD("org-1", "proj-2", 1)); err != ErrDecrypt {
		t.Fatalf("a wrapped key moved to another project unwrapped: %v", err)
	}
	if _, err := UnwrapDataKey(master, nonce, wrapped, DataKeyAAD("org-2", "proj-1", 1)); err != ErrDecrypt {
		t.Fatalf("a wrapped key moved to another organization unwrapped: %v", err)
	}
	if _, err := UnwrapDataKey(master, nonce, wrapped, DataKeyAAD("org-1", "proj-1", 2)); err != ErrDecrypt {
		t.Fatalf("a wrapped key relabelled to another key version unwrapped: %v", err)
	}
	if _, err := UnwrapDataKey(testKey(t, 23), nonce, wrapped, aad); err != ErrDecrypt {
		t.Fatalf("a wrapped key unwrapped under the wrong master key: %v", err)
	}
}

// TestChangePayloadBoundToChangeID checks a pending change's payload cannot be redirected.
func TestChangePayloadBoundToChangeID(t *testing.T) {
	master := testKey(t, 31)
	if NewSealer(master).Master() != master {
		t.Fatal("NewSealer did not retain the master key")
	}

	dataKey := &DataKey{orgID: "org-1", projectID: "proj-1", key: testKey(t, 32)}
	nonce, ct, err := dataKey.SealChange("org-1", "proj-1", "env-1", "API_KEY", "chg-1", []byte("proposed"))
	if err != nil {
		t.Fatalf("SealChange: %v", err)
	}

	// The same coordinates with a different change id must fail.
	if got, err := dataKey.OpenChange("org-1", "proj-1", "env-1", "API_KEY", "chg-2", nonce, ct); err == nil || got != nil {
		t.Fatalf("a change payload opened under another change id: %q", got)
	}
	// As must a different key, environment, project or organization.
	for name, got := range map[string]error{
		"key":     openChangeErr(dataKey, "org-1", "proj-1", "env-1", "OTHER", "chg-1", nonce, ct),
		"env":     openChangeErr(dataKey, "org-1", "proj-1", "env-2", "API_KEY", "chg-1", nonce, ct),
		"project": openChangeErr(dataKey, "org-1", "proj-2", "env-1", "API_KEY", "chg-1", nonce, ct),
		"org":     openChangeErr(dataKey, "org-2", "proj-1", "env-1", "API_KEY", "chg-1", nonce, ct),
	} {
		if got == nil {
			t.Fatalf("a change payload opened under another %s", name)
		}
	}

	// And the genuine coordinates must work.
	plain, err := dataKey.OpenChange("org-1", "proj-1", "env-1", "API_KEY", "chg-1", nonce, ct)
	if err != nil {
		t.Fatalf("OpenChange: %v", err)
	}
	if string(plain) != "proposed" {
		t.Fatalf("got %q", plain)
	}
}

func openChangeErr(d *DataKey, org, proj, env, key, change string, nonce, ct []byte) error {
	_, err := d.OpenChange(org, proj, env, key, change, nonce, ct)
	return err
}

// TestDataKeyRejectsForeignCoordinates checks the DataKey refuses to act outside its project even
// when the associated data would otherwise be built for it.
func TestDataKeyRejectsForeignCoordinates(t *testing.T) {
	d := &DataKey{orgID: "org-1", projectID: "proj-1", key: testKey(t, 41)}
	if _, _, err := d.Seal("org-1", "proj-2", "env-1", "KEY", 1, []byte("v")); err == nil {
		t.Fatal("a data key sealed for another project")
	}
	if _, err := d.Open("org-1", "proj-2", "env-1", "KEY", 1, make([]byte, NonceSize), make([]byte, TagSize)); err == nil {
		t.Fatal("a data key opened for another project")
	}
	var nilKey *DataKey
	if _, _, err := nilKey.Seal("org-1", "proj-1", "env-1", "KEY", 1, []byte("v")); err == nil {
		t.Fatal("a nil data key sealed")
	}
}

// TestParseKey covers the master-key gate: base64, exactly 32 bytes, whitespace tolerated.
func TestParseKey(t *testing.T) {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	good := base64.StdEncoding.EncodeToString(raw)

	k, err := ParseKey(good)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if !bytes.Equal(k[:], raw) {
		t.Fatal("ParseKey produced the wrong bytes")
	}

	if _, err := ParseKey("  " + good + "\n"); err != nil {
		t.Fatalf("ParseKey with surrounding whitespace: %v", err)
	}
	if _, err := ParseKey(base64.RawStdEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("ParseKey unpadded: %v", err)
	}

	cases := map[string]error{
		"":             ErrKeyMissing,
		"   ":          ErrKeyMissing,
		"not base64!!": ErrKeyFormat,
		base64.StdEncoding.EncodeToString(raw[:16]):       ErrKeySize,
		base64.StdEncoding.EncodeToString(raw[:31]):       ErrKeySize,
		base64.StdEncoding.EncodeToString(append(raw, 0)): ErrKeySize,
	}
	for in, want := range cases {
		if _, err := ParseKey(in); err != want {
			t.Errorf("ParseKey(%q) = %v, want %v", in, err, want)
		}
	}
}

// TestKeyIsRedactedInFormatting checks a key cannot reach a log through %v, %s, %x-of-struct or %#v.
func TestKeyIsRedactedInFormatting(t *testing.T) {
	var k Key
	for i := range k {
		k[i] = 0xab
	}
	hexOfKey := fmt.Sprintf("%x", k[:])

	for _, format := range []string{"%v", "%s", "%#v", "%+v"} {
		out := fmt.Sprintf(format, k)
		if strings.Contains(out, hexOfKey) || strings.Contains(out, "abab") {
			t.Errorf("%s leaked the key: %s", format, out)
		}
	}

	type wrapper struct {
		K Key
		P string
	}
	out := fmt.Sprintf("%v %+v", wrapper{K: k, P: "x"}, wrapper{K: k, P: "x"})
	if strings.Contains(out, "abab") {
		t.Errorf("a struct containing a key leaked it: %s", out)
	}

	if !k.IsZero() == false {
		t.Error("IsZero reported true for a non-zero key")
	}
	if !(Key{}).IsZero() {
		t.Error("IsZero reported false for a zero key")
	}
}

// TestNewSealerFromBytesRejectsWrongLength checks the sealer gate.
func TestNewSealerFromBytesRejectsWrongLength(t *testing.T) {
	if _, err := NewSealerFromBytes(make([]byte, 16)); err != ErrKeySize {
		t.Fatalf("16-byte master key accepted: %v", err)
	}
	if _, err := NewSealerFromBytes(make([]byte, 32)); err != nil {
		t.Fatalf("32-byte master key refused: %v", err)
	}
}

// TestRotateIfNeededIsNoOpWithoutOldKey checks the boot path does nothing when no rotation is in
// progress, before it ever touches the database.
func TestRotateIfNeededIsNoOpWithoutOldKey(t *testing.T) {
	if err := RotateIfNeeded(t.Context(), nil, Key{}, testKey(t, 1)); err != nil {
		t.Fatalf("rotation with no old key should be a no-op, got %v", err)
	}
	if err := RotateIfNeeded(t.Context(), nil, testKey(t, 1), testKey(t, 2)); err == nil {
		t.Fatal("rotation without a pool should fail")
	}
}

// TestNewKeyIsRandom checks two generated keys differ and are the right size.
func TestNewKeyIsRandom(t *testing.T) {
	a, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	b, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if a == b {
		t.Fatal("two generated keys are identical")
	}
	if a.IsZero() || b.IsZero() {
		t.Fatal("a generated key is zero")
	}
}
