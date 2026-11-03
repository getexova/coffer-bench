package crypto

// WrapDataKey encrypts a project data key under the master key with the data-key associated data.
// It returns the nonce and the wrapped key, which are stored as project_data_keys.nonce and
// project_data_keys.wrapped_key.
func WrapDataKey(master, dek Key, aad []byte) (nonce, wrapped []byte, err error) {
	return Seal(master, dek[:], aad)
}

// UnwrapDataKey decrypts a wrapped project data key. A wrapped key from another project, another
// key version or another organization fails authentication and returns ErrDecrypt: the caller must
// treat that as a hard error and never fall back to an unencrypted path.
func UnwrapDataKey(master Key, nonce, wrapped, aad []byte) (Key, error) {
	var dek Key
	plaintext, err := Open(master, nonce, wrapped, aad)
	if err != nil {
		return Key{}, ErrDecrypt
	}
	if len(plaintext) != KeySize {
		zero(plaintext)
		return Key{}, ErrDecrypt
	}
	copy(dek[:], plaintext)
	zero(plaintext)
	return dek, nil
}
