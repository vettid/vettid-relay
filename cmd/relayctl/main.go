// Command relayctl is a small client for exercising a VettID relay: key
// generation, registration, token minting, deposit, collect, revoke, blobs,
// and a one-shot end-to-end smoke test.
//
//	relayctl [-url URL] <command> [flags]
//
// The relay URL defaults to $RELAY_URL or http://localhost:8080 and is also
// the token audience (it must equal the relay's RELAY_BASE_URL exactly).
//
// Key files hold the base64 Ed25519 seed (mode 0600). They are test keys for
// smoke testing — production principals keep relay keys in their vault or
// platform keystore.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
	client "github.com/vettid/vettid-relay/relayclient"
)

const usage = `usage: relayctl [-url URL] <command> [flags]

commands:
  keygen   -out FILE                         write a new key (base64 seed, 0600)
  id       -key FILE                         print mailbox id and public key
  register -key FILE                         register the key's mailbox
  mint     -key OWNER -sender PUBKEY_B64 [-ttl 720h] [-jti ID]
                                             mint a deposit token (printed to stdout)
  mint-open -key OWNER [-ttl 5m] [-jti ID]   mint a one-shot open token (first contact)
  claim-put -key OWNER (-data TEXT | -file PATH | stdin) [-ttl 15m]
                                             leave a single-fetch claim; prints claim_id
  claim-get -id CLAIM_ID [-out PATH]         fetch (and thereby delete) a claim; no key needed
  deposit  -key SENDER -to MAILBOX -token TOKEN (-data TEXT | -file PATH | stdin)
  collect  -key OWNER [-wait 25] [-max 32] [-ack] [-follow]
  revoke   -key OWNER (-jti ID | -sub PUBKEY_B64)
  delete-mailbox -key OWNER -confirm MAILBOX_ID
                                             delete the key's mailbox and everything in it
  blob-put -key SENDER -to MAILBOX -token TOKEN -file PATH
  blob-get -key OWNER -id BLOB_ID [-out PATH] [-delete]
  smoke                                      full end-to-end check with two throwaway keys
`

func main() {
	base := flag.String("url", envOr("RELAY_URL", "http://localhost:8080"), "relay base URL (also the token audience)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	url := strings.TrimRight(*base, "/")
	if err := dispatch(ctx, url, flag.Arg(0), flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relayctl:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func dispatch(ctx context.Context, url, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	keyFile := fs.String("key", "", "key file")
	out := fs.String("out", "", "output file")
	sender := fs.String("sender", "", "sender public key (base64)")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "token lifetime")
	jti := fs.String("jti", "", "token id")
	sub := fs.String("sub", "", "sender public key to revoke")
	to := fs.String("to", "", "recipient mailbox id")
	token := fs.String("token", "", "deposit token")
	data := fs.String("data", "", "payload text")
	file := fs.String("file", "", "payload file")
	wait := fs.Int("wait", 25, "long-poll wait seconds")
	max := fs.Int("max", 32, "max messages per collect")
	ack := fs.Bool("ack", false, "ack collected messages")
	follow := fs.Bool("follow", false, "keep collecting")
	id := fs.String("id", "", "blob id")
	del := fs.Bool("delete", false, "delete the blob after fetching")
	confirm := fs.String("confirm", "", "the mailbox id being deleted (delete-mailbox)")
	fs.Parse(args)

	load := func() (*client.Client, error) {
		if *keyFile == "" {
			return nil, errors.New("-key is required")
		}
		k, err := readKey(*keyFile)
		if err != nil {
			return nil, err
		}
		return client.New(url, k), nil
	}

	switch cmd {
	case "keygen":
		if *out == "" {
			return errors.New("-out is required")
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed()))
		if err == nil {
			c := client.New(url, priv)
			fmt.Printf("mailbox_id %s\npubkey     %s\n", c.MailboxID(), c.PublicKeyB64())
		}
		return err
	case "id":
		c, err := load()
		if err != nil {
			return err
		}
		fmt.Printf("mailbox_id %s\npubkey     %s\n", c.MailboxID(), c.PublicKeyB64())
		return nil
	case "register":
		c, err := load()
		if err != nil {
			return err
		}
		reg, err := c.Register(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("mailbox_id %s (created=%v)\naddress    %s@%s\n", reg.MailboxID, reg.Created, reg.MailboxID, url)
		return nil
	case "mint":
		c, err := load()
		if err != nil {
			return err
		}
		if _, ok := auth.DecodeKey(*sender); !ok {
			return errors.New("-sender must be a base64 Ed25519 public key")
		}
		tok, err := c.MintToken(*sender, url, client.TokenOptions{TTL: *ttl, JTI: *jti})
		if err != nil {
			return err
		}
		fmt.Println(tok)
		return nil
	case "mint-open":
		c, err := load()
		if err != nil {
			return err
		}
		ttl := *ttl
		if !flagSet(fs, "ttl") {
			ttl = 5 * time.Minute
		}
		tok, err := c.MintOpenToken(url, ttl, *jti)
		if err != nil {
			return err
		}
		fmt.Println(tok)
		return nil
	case "claim-put":
		c, err := load()
		if err != nil {
			return err
		}
		data, err := readPayload(*data, *file)
		if err != nil {
			return err
		}
		var claimTTL time.Duration
		if flagSet(fs, "ttl") {
			claimTTL = *ttl
		}
		id, exp, err := c.PutClaim(ctx, data, claimTTL)
		if err != nil {
			return err
		}
		fmt.Printf("%s expires %s\n", id, exp.Format(time.RFC3339))
		return nil
	case "claim-get":
		if *id == "" {
			return errors.New("-id is required")
		}
		// Unauthenticated: any key will do for the client struct.
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		b, err := client.New(url, k).GetClaim(ctx, *id)
		if err != nil {
			return err
		}
		if *out != "" {
			return os.WriteFile(*out, b, 0o600)
		}
		_, err = os.Stdout.Write(b)
		return err
	case "deposit":
		c, err := load()
		if err != nil {
			return err
		}
		payload, err := readPayload(*data, *file)
		if err != nil {
			return err
		}
		msgID, err := c.Deposit(ctx, *to, *token, payload)
		if err != nil {
			return err
		}
		fmt.Println(msgID)
		return nil
	case "collect":
		c, err := load()
		if err != nil {
			return err
		}
		for {
			msgs, err := c.Collect(ctx, time.Duration(*wait)*time.Second, *max)
			if err != nil {
				return err
			}
			for _, m := range msgs {
				fmt.Printf("%s %s %d bytes %q\n", m.MsgID, m.DepositedAt, len(m.Payload), preview(m.Payload))
				if *ack {
					if err := c.Ack(ctx, m.MsgID); err != nil {
						return err
					}
				}
			}
			if !*follow {
				return nil
			}
		}
	case "revoke":
		c, err := load()
		if err != nil {
			return err
		}
		var r []client.Revocation
		if *jti != "" {
			r = append(r, client.Revocation{Kind: "jti", Value: *jti})
		}
		if *sub != "" {
			r = append(r, client.Revocation{Kind: "sub", Value: *sub})
		}
		if len(r) == 0 {
			return errors.New("-jti or -sub is required")
		}
		return c.Revoke(ctx, r...)
	case "delete-mailbox":
		c, err := load()
		if err != nil {
			return err
		}
		if *confirm != c.MailboxID() {
			return fmt.Errorf("refusing to delete: -confirm must be the key's mailbox id (%s)", c.MailboxID())
		}
		if err := c.DeleteMailbox(ctx); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", c.MailboxID())
		return nil
	case "blob-put":
		c, err := load()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		blobID, exp, err := c.PutBlob(ctx, *to, *token, b)
		if err != nil {
			return err
		}
		fmt.Printf("%s expires %s\n", blobID, exp.Format(time.RFC3339))
		return nil
	case "blob-get":
		c, err := load()
		if err != nil {
			return err
		}
		b, err := c.GetBlob(ctx, *id)
		if err != nil {
			return err
		}
		if *out != "" {
			err = os.WriteFile(*out, b, 0o600)
		} else {
			_, err = os.Stdout.Write(b)
		}
		if err == nil && *del {
			err = c.DeleteBlob(ctx, *id)
		}
		return err
	case "smoke":
		return smoke(ctx, url)
	default:
		flag.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a base64 32-byte seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readPayload(data, file string) ([]byte, error) {
	switch {
	case data != "":
		return []byte(data), nil
	case file != "":
		return os.ReadFile(file)
	default:
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
}

func preview(b []byte) string {
	if len(b) > 40 {
		b = b[:40]
	}
	return string(b)
}

// smoke runs register → mint → long-poll deposit/collect (latency) → ack →
// blob put/get/delete → revoke → rejected deposit → mailbox delete, with
// throwaway keys (deleted again at the end on relays ≥ 0.5.0).
// NOTE: payloads here are plaintext test strings; real clients deposit only
// end-to-end ciphertext.
func smoke(ctx context.Context, url string) error {
	newKey := func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }
	owner, sender := client.New(url, newKey()), client.New(url, newKey())
	step := func(name string, err error) error {
		if err != nil {
			fmt.Printf("FAIL %-28s %v\n", name, err)
			return err
		}
		fmt.Printf("ok   %s\n", name)
		return nil
	}
	reg, err := owner.Register(ctx)
	if err := step("register owner", err); err != nil {
		return err
	}
	if _, err := sender.Register(ctx); step("register sender", err) != nil {
		return err
	}
	tok, err := owner.MintToken(sender.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour})
	if err := step("mint token", err); err != nil {
		return err
	}
	type res struct {
		msgs []client.Message
		at   time.Time
		err  error
	}
	got := make(chan res, 1)
	go func() {
		m, err := owner.Collect(ctx, 25*time.Second, 10)
		got <- res{m, time.Now(), err}
	}()
	time.Sleep(500 * time.Millisecond) // let the collect park
	start := time.Now()
	msgID, err := sender.Deposit(ctx, reg.MailboxID, tok, []byte("relayctl smoke test"))
	if err := step("deposit", err); err != nil {
		return err
	}
	r := <-got
	if r.err == nil && (len(r.msgs) != 1 || r.msgs[0].MsgID != msgID) {
		r.err = fmt.Errorf("collected %d messages, want %s", len(r.msgs), msgID)
	}
	if err := step(fmt.Sprintf("long-poll collect (%v)", r.at.Sub(start).Round(time.Millisecond)), r.err); err != nil {
		return err
	}
	if err := step("ack", owner.Ack(ctx, msgID)); err != nil {
		return err
	}
	if reg.Limits.MaxBlobBytes != nil {
		blob := bytes.Repeat([]byte{0xA5}, 1<<20)
		id, _, err := sender.PutBlob(ctx, reg.MailboxID, tok, blob)
		if err := step("blob put (1 MiB)", err); err != nil {
			return err
		}
		b, err := owner.GetBlob(ctx, id)
		if err == nil && !bytes.Equal(b, blob) {
			err = errors.New("blob content mismatch")
		}
		if err := step("blob get", err); err != nil {
			return err
		}
		if err := step("blob delete", owner.DeleteBlob(ctx, id)); err != nil {
			return err
		}
	}
	// First contact: claim + one-shot open token for a key the owner has
	// never seen.
	stranger := client.New(url, newKey())
	bundle := []byte("relayctl smoke bundle")
	claimID, _, err := owner.PutClaim(ctx, bundle, 0)
	if err := step("claim put", err); err != nil {
		return err
	}
	fetched, err := stranger.GetClaim(ctx, claimID)
	if err == nil && !bytes.Equal(fetched, bundle) {
		err = errors.New("claim content mismatch")
	}
	if err := step("claim get (unauthenticated)", err); err != nil {
		return err
	}
	if _, err = stranger.GetClaim(ctx, claimID); client.IsCode(err, "claim_unknown") {
		err = nil
	} else if err == nil {
		err = errors.New("claim fetched twice")
	}
	if err := step("claim is single-fetch", err); err != nil {
		return err
	}
	openTok, err := owner.MintOpenToken(url, 2*time.Minute, "")
	if err := step("mint open token", err); err != nil {
		return err
	}
	firstID, err := stranger.Deposit(ctx, reg.MailboxID, openTok, []byte("first contact"))
	if err := step("open-token deposit", err); err != nil {
		return err
	}
	if _, err = stranger.Deposit(ctx, reg.MailboxID, openTok, []byte("again")); client.IsCode(err, "token_used") {
		err = nil
	} else if err == nil {
		err = errors.New("open token accepted twice")
	}
	if err := step("open token is one-shot", err); err != nil {
		return err
	}
	msgs, err := owner.Collect(ctx, 5*time.Second, 10)
	if err == nil && (len(msgs) != 1 || msgs[0].MsgID != firstID || msgs[0].Sender != stranger.PublicKeyB64()) {
		err = fmt.Errorf("unexpected collect result (%d messages)", len(msgs))
	}
	if err := step("collect shows the stranger as sender", err); err != nil {
		return err
	}
	if err := step("ack", owner.Ack(ctx, firstID)); err != nil {
		return err
	}
	if err := step("revoke sender", owner.Revoke(ctx, client.Revocation{Kind: "sub", Value: sender.PublicKeyB64()})); err != nil {
		return err
	}
	_, err = sender.Deposit(ctx, reg.MailboxID, tok, []byte("must fail"))
	if client.IsCode(err, "token_revoked") {
		err = nil
	} else if err == nil {
		err = errors.New("deposit accepted after revocation")
	}
	if err := step("revoked deposit rejected", err); err != nil {
		return err
	}
	// Mailbox deletion (0.5.0): a parked collect ends with mailbox_unknown,
	// later deposits are refused, and the throwaway keys leave nothing
	// behind. A relay before 0.5.0 has no such route (not_found): skipped.
	parked := make(chan error, 1)
	go func() { _, err := owner.Collect(ctx, 25*time.Second, 10); parked <- err }()
	time.Sleep(500 * time.Millisecond) // let the collect park
	err = owner.DeleteMailbox(ctx)
	if client.IsCode(err, "not_found") {
		<-parked
		fmt.Println("skip mailbox delete (relay < 0.5.0)")
		fmt.Println("smoke test passed")
		return nil
	}
	if err := step("delete mailbox", err); err != nil {
		return err
	}
	perr := <-parked
	if client.IsCode(perr, "mailbox_unknown") {
		perr = nil
	} else if perr == nil {
		perr = errors.New("parked collect not ended by the deletion")
	}
	if err := step("parked collect ended (mailbox_unknown)", perr); err != nil {
		return err
	}
	fresh, err := owner.MintToken(stranger.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour})
	if err == nil {
		_, err = stranger.Deposit(ctx, reg.MailboxID, fresh, []byte("must fail"))
		if client.IsCode(err, "mailbox_unknown") {
			err = nil
		} else if err == nil {
			err = errors.New("deposit accepted after deletion")
		}
	}
	if err := step("deposit after delete rejected", err); err != nil {
		return err
	}
	if err := step("delete is idempotent", owner.DeleteMailbox(ctx)); err != nil {
		return err
	}
	if err := step("delete sender mailbox", sender.DeleteMailbox(ctx)); err != nil {
		return err
	}
	fmt.Println("smoke test passed")
	return nil
}
