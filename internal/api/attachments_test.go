package api

// C2.4 tests: attachment size cap (413), owner-only retrieval (404
// cross-user, J3), oversize rejection mid-stream.

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestAttachmentRoundtripOwnerOnly(t *testing.T) {
	s, u1, u2 := syncTestEnv(t)
	blob := bytes.Repeat([]byte{0xAB}, 1024)

	// PUT (raw body = the envelope bytes)
	rec, resp := u1.ctx.do(t, s, http.MethodPut, "/api/attachments", blobBytes(blob))
	if rec.Code != http.StatusCreated {
		t.Fatalf("put = %d: %v", rec.Code, resp)
	}
	attachmentID, _ := resp["attachmentId"].(string)
	if attachmentID == "" {
		t.Fatal("no attachmentId")
	}
	if size, _ := resp["size"].(float64); int(size) != len(blob) {
		t.Fatalf("size = %v", resp["size"])
	}

	// owner GET
	rec2, _ := u1.ctx.do(t, s, http.MethodGet, "/api/attachments/"+attachmentID, nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("owner get = %d", rec2.Code)
	}
	if got := rec2.Body.Bytes(); len(got) != len(blob) || got[0] != 0xAB {
		t.Fatal("blob mutated in storage")
	}

	// other user GET ⇒ 404 (never 403 — J3)
	rec3, _ := u2.ctx.do(t, s, http.MethodGet, "/api/attachments/"+attachmentID, nil)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("cross-user get = %d, want 404", rec3.Code)
	}

	// nonexistent id ⇒ 404
	rec4, _ := u1.ctx.do(t, s, http.MethodGet, "/api/attachments/00000000-0000-4000-8000-000000000000", nil)
	if rec4.Code != http.StatusNotFound {
		t.Fatalf("missing get = %d, want 404", rec4.Code)
	}
}

func blobBytes(b []byte) []byte { return b }

func TestAttachmentTooSmall(t *testing.T) {
	s, u1, _ := syncTestEnv(t)
	rec, _ := u1.ctx.do(t, s, http.MethodPut, "/api/attachments", blobBytes([]byte("tiny")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tiny blob = %d, want 400", rec.Code)
	}
}

func TestAttachmentOversize413(t *testing.T) {
	s, u1, _ := syncTestEnv(t)
	// 10 MiB + 1 byte — must be rejected by MaxBytesReader mid-stream
	huge := bytes.Repeat([]byte{0x01}, maxAttachmentBytes+1)
	rec, resp := u1.ctx.do(t, s, http.MethodPut, "/api/attachments", blobBytes(huge))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d, want 413 (body %v)", rec.Code, resp)
	}
}

var _ = base64.StdEncoding
