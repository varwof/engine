// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"testing"
)

// FuzzParseWALLines ensures WAL replay never panics on arbitrary line content:
// a corrupt WAL after a crash is the most adversarial input the buffer can see.
func FuzzParseWALLines(f *testing.F) {
	f.Add([]byte("# comment\n"))
	f.Add([]byte(`{"SerialNumber":"1","CAName":"ca","Status":"V"}` + "\n"))
	f.Add([]byte(`{"kind":"cert","cert":{"SerialNumber":"1","CAName":"ca"}}` + "\n"))
	f.Add([]byte(`{"kind":"da_nonce","nonce":"c2FtcGxlbm9uY2VjMDAwMDAwMDAwMDAwMDAw"}` + "\n"))
	f.Add([]byte("garbage\n"))
	f.Add([]byte("{not json\n"))
	f.Add([]byte("valid\nvalid2\n\n#comment\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		items := parseWALLines(data)
		for _, it := range items {
			if it.Kind == KindCert && it.Cert == nil {
				t.Fatal("parseWALLines returned a cert item with a nil record")
			}
			if it.Kind == KindDANonce && len(it.Nonce) != 32 {
				t.Fatal("parseWALLines returned a da_nonce item with a non-32-byte nonce")
			}
		}
	})
}
