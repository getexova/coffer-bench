package crypto

import (
	"encoding/binary"
	"strconv"
)

// Associated-data domains. These strings are frozen (docs/CONTRACTS.md §5): changing one would
// make every existing ciphertext undecryptable, so they are constants and never configurable.
const (
	domainSecretValue = "coffer:v1"
	domainDataKey     = "coffer:dek:v1"
	domainChange      = "coffer:change:v1"
)

// AAD builds the frozen associated-data encoding: for each part, its length as an unsigned varint
// followed by its bytes.
//
// The length prefixes are the security property. Without them, parts ("ab","c") and ("a","bc")
// would encode to the same bytes, and a value could be shifted across a field boundary to forge a
// tag that verifies. With them the encoding is unambiguous and prefix-free.
func AAD(parts ...string) []byte {
	var out []byte
	var scratch [binary.MaxVarintLen64]byte
	for _, p := range parts {
		n := binary.PutUvarint(scratch[:], uint64(len(p)))
		out = append(out, scratch[:n]...)
		out = append(out, p...)
	}
	return out
}

// SecretAAD is the associated data for a secret value: domain, organization, project,
// environment, key and version. A ciphertext for version 3 of API_KEY in prod cannot be opened as
// version 4, as a different key, or in another environment or organization.
func SecretAAD(orgID, projectID, envID, key string, version int64) []byte {
	return AAD(domainSecretValue, orgID, projectID, envID, key, strconv.FormatInt(version, 10))
}

// DataKeyAAD is the associated data for a wrapped project data key: domain, organization, project
// and data-key version. A wrapped key cannot be moved to another project's row.
func DataKeyAAD(orgID, projectID string, keyVersion int) []byte {
	return AAD(domainDataKey, orgID, projectID, strconv.Itoa(keyVersion))
}

// ChangeAAD is the associated data for the proposed value held by a pending change request:
// domain, organization, project, environment, key and change id.
//
// Binding to the change id means a pending payload is ciphertext at rest and cannot be redirected
// to another key, environment or request by editing the row.
func ChangeAAD(orgID, projectID, envID, key, changeID string) []byte {
	return AAD(domainChange, orgID, projectID, envID, key, changeID)
}
