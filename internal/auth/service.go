package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bytemare/opaque"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service implements the OPAQUE server half plus user persistence for
// the auth endpoints. One instance for the server's lifetime; the
// underlying opaque.Server is goroutine-safe for concurrent GenerateKE2
// / RegistrationResponse calls.
//
// Wire note: serenity clients send base64url-no-pad; §P2-0 HTTP
// carries padded std base64. decodeOpaqueB64 accepts either alphabet —
// the payload bytes are identical — and responses are always std-padded.
type Service struct {
	srv     *opaque.Server
	conf    *opaque.Configuration
	deser   *opaque.Deserializer
	pool    *pgxpool.Pool
	logger  *slog.Logger
	pending *pendingLogins
}

// NewService builds the service from the persistent ServerSetup
// (oprf_seed||sk||dummy_pk, 128 B — see docs/OPAQUE-INTEROP.md). The
// setup is stored once and reused across restarts so records stay valid.
func NewService(pool *pgxpool.Pool, logger *slog.Logger, serverSetupB64 string) (*Service, error) {
	setupBytes, err := decodeOpaqueB64(serverSetupB64)
	if err != nil {
		return nil, fmt.Errorf("auth: decode OPAQUE_SERVER_SETUP: %w", err)
	}
	if len(setupBytes) != 128 {
		return nil, fmt.Errorf("auth: OPAQUE_SERVER_SETUP: want 128 bytes, got %d", len(setupBytes))
	}
	srv, deser, err := serverFromSetup(setupBytes)
	if err != nil {
		return nil, err
	}
	return &Service{
		srv:     srv,
		conf:    spikeConfiguration(),
		deser:   deser,
		pool:    pool,
		logger:  logger,
		pending: newPendingLogins(),
	}, nil
}

// serverFromSetup transplants a serenity/opaque-ke ServerSetup into a
// Go opaque.Server (layout proven by the C2.0 interop tests).
func serverFromSetup(setup []byte) (*opaque.Server, *opaque.Deserializer, error) {
	conf := spikeConfiguration()
	srv, err := opaque.NewServer(conf)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: NewServer: %w", err)
	}
	sk := opaque.RistrettoSha512.Group().NewScalar()
	if err := sk.Decode(setup[64:96]); err != nil {
		return nil, nil, fmt.Errorf("auth: server setup sk: %w", err)
	}
	pk := opaque.RistrettoSha512.Group().Base().Multiply(sk)
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil, // serenity default: identity = static pks (OPAQUE-INTEROP.md)
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: setup[:64],
	}
	if err := srv.SetKeyMaterial(skm); err != nil {
		return nil, nil, fmt.Errorf("auth: SetKeyMaterial: %w", err)
	}
	deser, err := conf.Deserializer()
	if err != nil {
		return nil, nil, fmt.Errorf("auth: deserializer: %w", err)
	}
	return srv, deser, nil
}

// GenerateServerSetup creates a fresh ServerSetup for first boot,
// serenity-compatible raw bytes (128 B), std-b64 encoded. The caller
// persists it (OPAQUE_SERVER_SETUP env) — regenerating invalidates
// every stored record.
func GenerateServerSetup() (string, error) {
	seed := make([]byte, 64) // sha512 output = OPRF seed length
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("auth: generate oprf seed: %w", err)
	}
	sk := opaque.RistrettoSha512.Group().NewScalar().Random()
	setup := make([]byte, 0, 128)
	setup = append(setup, seed...)
	setup = append(setup, sk.Encode()...)
	// Third block is opaque-ke's dummy_pk (used ONLY for unknown-user
	// fake responses — see OPAQUE-INTEROP.md); a deterministic element
	// is valid there. The real AKE pk = sk·G is derived at load, so it
	// is not stored.
	dummy := opaque.RistrettoSha512.Group().HashToGroup([]byte("fincrypt-dummy-pk"), opaque.RistrettoSha512.Group().MakeDST("fincrypt/dummy", 1))
	setup = append(setup, dummy.Encode()...)
	sk.Zero()
	return base64.StdEncoding.EncodeToString(setup), nil
}

// decodeOpaqueB64 decodes std-padded or url-no-pad base64 (either
// alphabet, since OPAQUE peers legitimately emit both).
func decodeOpaqueB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// ─── request/response shapes (§P2-0) ─────────────────────────────────

// RegisterStartBody is POST /api/auth/register/start.
type RegisterStartBody struct {
	Email             string `json:"email"`
	RegistrationReq   string `json:"registrationRequest"` // b64 (either alphabet in)
}

// RegisterStartResponse is the 200 response. KdfSalt is fresh-random
// 32 B; KdfParams echoes the client proposal after D7 validation.
type RegisterStartResponse struct {
	RegistrationResp string          `json:"registrationResponse"` // std b64
	KdfSalt          string          `json:"kdfSalt"`              // std b64, 32 B
	KdfParams        json.RawMessage `json:"kdfParams"`
}

// KDFParams is the wire shape of the Argon2id params (P1 §P1-0 shape).
type KDFParams struct {
	Alg     string `json:"alg"`
	M       int    `json:"m"` // KiB
	T       int    `json:"t"`
	P       int    `json:"p"`
	Version int    `json:"version"`
}

// allowedKDFParams is the D7 downgrade-defense set: exactly the v1
// profile. Anything else ⇒ 400 at the door.
func allowedKDFParams(raw json.RawMessage) error {
	var p KDFParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("kdf_params: not an object")
	}
	// Version = Argon2's algorithm version (0x13 = 19), the only value
	// P1's kdf.ts emits; the D7 guard pins the whole profile.
	if p.Alg != "argon2id" || p.M != 65536 || p.T != 3 || p.P != 4 || p.Version != 19 {
		return errors.New("kdf_params outside the allowed set (D7)")
	}
	return nil
}

// RegisterFinishBody is POST /api/auth/register/finish.
type RegisterFinishBody struct {
	Email              string          `json:"email"`
	RegistrationRec    string          `json:"registrationRecord"` // b64
	WrappedDek         string          `json:"wrappedDek"`         // b64 (client-encrypted)
	WrappedDekRecovery string          `json:"wrappedDekRecovery"` // b64
	KdfSalt            string          `json:"kdfSalt"`            // b64 from register/start
	KdfParams          json.RawMessage `json:"kdfParams"`
}

// LoginStartBody is POST /api/auth/login/start.
type LoginStartBody struct {
	Email      string `json:"email"`
	StartLogin string `json:"startLoginRequest"` // b64
}

// LoginFinishBody is POST /api/auth/login/finish.
type LoginFinishBody struct {
	Email       string `json:"email"`
	FinishLogin string `json:"finishLoginRequest"` // b64
}

// LoginFinishResponse returns the unlock material on success.
type LoginFinishResponse struct {
	UserID             string          `json:"userId"`
	KdfSalt            string          `json:"kdfSalt"`
	KdfParams          json.RawMessage `json:"kdfParams"`
	WrappedDek         string          `json:"wrappedDek"`
	WrappedDekRecovery string          `json:"wrappedDekRecovery"`
}

// userRow mirrors the users table (001).
type userRow struct {
	ID            string
	Email         string
	OpaqueRecord  []byte
	KdfSalt       []byte
	KdfParams     json.RawMessage
	WrappedDek    []byte
	WrappedDekRec []byte
}

// ─── sentinel errors (mapped to HTTP at the door) ────────────────────

var (
	// ErrUnknownUser means no such account (D8: login uses the fake-record path).
	ErrUnknownUser = errors.New("auth: unknown user")
	// ErrEmailTaken is a 409 at register-finish.
	ErrEmailTaken = errors.New("auth: email already registered")
	// ErrNoPendingLogin means login/finish arrived without a matching start.
	ErrNoPendingLogin = errors.New("auth: no pending login (expired or out of order)")
	// ErrInvalidCredentials covers OPAQUE MAC failure at login/finish.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
)

// ─── registration ────────────────────────────────────────────────────

// RegisterStart handles the OPRF evaluation half of registration and
// mints the kdf_salt the client will use for its passphrase KEK.
func (s *Service) RegisterStart(_ context.Context, email, registrationReqB64 string) (respB64, kdfSaltB64 string, err error) {
	reqBytes, err := decodeOpaqueB64(registrationReqB64)
	if err != nil {
		return "", "", fmt.Errorf("auth: registrationRequest: %w", err)
	}
	req, err := s.deser.RegistrationRequest(reqBytes)
	if err != nil {
		return "", "", fmt.Errorf("auth: registrationRequest: %w", err)
	}
	resp, err := s.srv.RegistrationResponse(req, []byte(email), nil)
	if err != nil {
		return "", "", fmt.Errorf("auth: registration response: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("auth: kdf salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(resp.Serialize()),
		base64.StdEncoding.EncodeToString(salt), nil
}

// RegisterFinish persists the user. Duplicate email ⇒ ErrEmailTaken
// (409 at the door — citext uniqueness is only revealed after the
// OPAQUE handshake completes, where enumeration is no longer at stake).
func (s *Service) RegisterFinish(ctx context.Context, b RegisterFinishBody) (userID string, err error) {
	recordBytes, err := decodeOpaqueB64(b.RegistrationRec)
	if err != nil {
		return "", fmt.Errorf("auth: registrationRecord: %w", err)
	}
	record, err := s.deser.RegistrationRecord(recordBytes)
	if err != nil {
		return "", fmt.Errorf("auth: registrationRecord: %w", err)
	}
	if err := allowedKDFParams(b.KdfParams); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	salt, err := decodeOpaqueB64(b.KdfSalt)
	if err != nil || len(salt) != 32 {
		return "", errors.New("auth: kdfSalt must be the 32 B b64 issued at register/start")
	}
	wrappedDek, err := decodeOpaqueB64(b.WrappedDek)
	if err != nil || len(wrappedDek) < 40 {
		return "", errors.New("auth: wrappedDek missing/short")
	}
	wrappedRec, err := decodeOpaqueB64(b.WrappedDekRecovery)
	if err != nil || len(wrappedRec) < 40 {
		return "", errors.New("auth: wrappedDekRecovery missing/short")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx,
		`insert into users (email, opaque_record, kdf_salt, kdf_params, wrapped_dek, wrapped_dek_recovery)
		 values ($1, $2, $3, $4, $5, $6) returning id::text`,
		b.Email, record.Serialize(), salt, b.KdfParams, wrappedDek, wrappedRec,
	).Scan(&id)
	if err != nil {
		if pgErrUnique(err) {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("auth: insert user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("auth: commit: %w", err)
	}
	return id, nil
}

// pgErrUnique reports whether err is SQLSTATE 23505 (unique violation).
func pgErrUnique(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// ─── login ───────────────────────────────────────────────────────────

// LoginStart evaluates the OPRF + masking layer. Unknown users get the
// fake-record path — identical response shape (D8 anti-enumeration).
func (s *Service) LoginStart(ctx context.Context, email, startLoginB64 string) (respB64 string, err error) {
	ke1Bytes, err := decodeOpaqueB64(startLoginB64)
	if err != nil {
		return "", fmt.Errorf("auth: startLoginRequest: %w", err)
	}
	ke1, err := s.deser.KE1(ke1Bytes)
	if err != nil {
		return "", fmt.Errorf("auth: startLoginRequest: %w", err)
	}

	row, err := s.lookupUser(ctx, email)
	if errors.Is(err, ErrUnknownUser) {
		fake, ferr := s.conf.GetFakeRecord([]byte(email))
		if ferr != nil {
			return "", fmt.Errorf("auth: fake record: %w", ferr)
		}
		ke2, _, ferr := s.srv.GenerateKE2(ke1, fake)
		if ferr != nil {
			return "", fmt.Errorf("auth: fake ke2: %w", ferr)
		}
		return base64.StdEncoding.EncodeToString(ke2.Serialize()), nil
	}
	if err != nil {
		return "", err
	}

	record, err := s.deser.RegistrationRecord(row.OpaqueRecord)
	if err != nil {
		return "", fmt.Errorf("auth: stored record: %w", err)
	}
	ke2, out, err := s.srv.GenerateKE2(ke1, &opaque.ClientRecord{
		CredentialIdentifier: []byte(email),
		ClientIdentity:       record.ClientPublicKey.Encode(), // serenity default ids = static pks
		RegistrationRecord:  record,
	})
	if err != nil {
		return "", fmt.Errorf("auth: ke2: %w", err)
	}
	// The KE2 is stateful: its client MAC is verified at finish. Park it.
	if err := s.pending.put(email, out.ClientMAC); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ke2.Serialize()), nil
}

// LoginFinish verifies the client's KE3 and returns the unlock
// material. A wrong password fails the MAC check ⇒ ErrInvalidCredentials.
func (s *Service) LoginFinish(ctx context.Context, b LoginFinishBody) (*LoginFinishResponse, error) {
	ke3Bytes, err := decodeOpaqueB64(b.FinishLogin)
	if err != nil {
		return nil, fmt.Errorf("auth: finishLoginRequest: %w", err)
	}
	ke3, err := s.deser.KE3(ke3Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: finishLoginRequest: %w", err)
	}
	row, err := s.lookupUser(ctx, b.Email)
	if err != nil {
		return nil, err
	}
	out, ok := s.pending.pop(b.Email)
	if !ok {
		return nil, ErrNoPendingLogin
	}
	if err := s.srv.LoginFinish(ke3, out); err != nil {
		return nil, ErrInvalidCredentials
	}
	return &LoginFinishResponse{
		UserID:             row.ID,
		KdfSalt:            base64.StdEncoding.EncodeToString(row.KdfSalt),
		KdfParams:          row.KdfParams,
		WrappedDek:         base64.StdEncoding.EncodeToString(row.WrappedDek),
		WrappedDekRecovery: base64.StdEncoding.EncodeToString(row.WrappedDekRec),
	}, nil
}

// MeResponse is GET /api/auth/me (§P2-0 Session row).
type MeResponse struct {
	UserID    string          `json:"userId"`
	Email     string          `json:"email"`
	KdfSalt   string          `json:"kdfSalt"`
	KdfParams json.RawMessage `json:"kdfParams"`
}

// Me returns the session user's identity and KDF material.
func (s *Service) Me(ctx context.Context, userID string) (*MeResponse, error) {
	row := &userRow{}
	err := s.pool.QueryRow(ctx,
		`select id::text, email::text, kdf_salt, kdf_params from users where id = $1`, userID,
	).Scan(&row.ID, &row.Email, &row.KdfSalt, &row.KdfParams)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownUser
	}
	if err != nil {
		return nil, fmt.Errorf("auth: me lookup: %w", err)
	}
	return &MeResponse{
		UserID:    row.ID,
		Email:     row.Email,
		KdfSalt:   base64.StdEncoding.EncodeToString(row.KdfSalt),
		KdfParams: row.KdfParams,
	}, nil
}

// lookupUser fetches by citext email; unknown ⇒ ErrUnknownUser.
func (s *Service) lookupUser(ctx context.Context, email string) (*userRow, error) {
	row := &userRow{}
	err := s.pool.QueryRow(ctx,
		`select id::text, email::text, opaque_record, kdf_salt, kdf_params, wrapped_dek, wrapped_dek_recovery
		 from users where email = $1`, email,
	).Scan(&row.ID, &row.Email, &row.OpaqueRecord, &row.KdfSalt, &row.KdfParams, &row.WrappedDek, &row.WrappedDekRec)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownUser
	}
	if err != nil {
		return nil, fmt.Errorf("auth: lookup user: %w", err)
	}
	return row, nil
}

// pendingLogins parks each in-flight login's expected client MAC between
// the two login steps. Keyed by email; bounded, expiring (single-replica
// v1 — D6/D8; multi-replica moves this to shared storage in P6).
type pendingLogins struct {
	ch  chan struct{}
	mu  sync.Mutex
	m   map[string]pendingEntry
}

type pendingEntry struct {
	mac      []byte
	deadline time.Time
}

const pendingTTL = 2 * time.Minute

func newPendingLogins() *pendingLogins {
	p := &pendingLogins{ch: make(chan struct{}, 1), m: make(map[string]pendingEntry)}
	go p.reaper()
	return p
}

func (p *pendingLogins) put(email string, mac []byte) error {
	// one pending login per email at a time — a second start replaces it
	// (same device retried, or an attacker racing a victim; the MAC only
	// validates the matching KE1, so cross-attachment fails the finish).
	select {
	case p.ch <- struct{}{}:
		p.mu.Lock()
		p.m[email] = pendingEntry{mac: mac, deadline: time.Now().Add(pendingTTL)}
		p.mu.Unlock()
		<-p.ch
	default:
		p.mu.Lock()
		p.m[email] = pendingEntry{mac: mac, deadline: time.Now().Add(pendingTTL)}
		p.mu.Unlock()
	}
	return nil
}

func (p *pendingLogins) pop(email string) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[email]
	if !ok || time.Now().After(e.deadline) {
		return nil, false
	}
	delete(p.m, email)
	return e.mac, true
}

func (p *pendingLogins) reaper() {
	for range time.Tick(30 * time.Second) {
		p.mu.Lock()
		now := time.Now()
		for k, e := range p.m {
			if now.After(e.deadline) {
				delete(p.m, k)
			}
		}
		p.mu.Unlock()
	}
}