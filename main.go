package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"filippo.io/age"

	kms "k8s.io/kms/pkg/service"
)

const (
	Version = "v2"
	OK      = "ok"
)

type server struct {
	keyId      string
	identity   age.Identity
	recipients []age.Recipient
}

func (s *server) Status(ctx context.Context) (*kms.StatusResponse, error) {
	resp := &kms.StatusResponse{
		Version: Version,
		Healthz: OK,
		KeyID:   s.keyId,
	}

	return resp, nil
}

func (s *server) Encrypt(ctx context.Context, uid string, plaintext []byte) (*kms.EncryptResponse, error) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()

	var ciphertext bytes.Buffer
	c, err := age.Encrypt(&ciphertext, s.recipients...)
	if err != nil {
		log.Printf("Failed to encrypt: %s", err)
		return nil, err
	}

	if _, err := c.Write(plaintext); err != nil {
		log.Printf("Failed to encrypt: %s", err)
		return nil, err
	}

	err = c.Close()
	if err != nil {
		log.Printf("Failed to encrypt: %s", err)
		return nil, err
	}

	resp := &kms.EncryptResponse{
		Ciphertext:  ciphertext.Bytes(),
		KeyID:       s.keyId,
		Annotations: make(map[string][]byte),
	}

	return resp, nil
}

func (s *server) Decrypt(ctx context.Context, uid string, req *kms.DecryptRequest) ([]byte, error) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()

	r, err := age.Decrypt(bytes.NewBuffer(req.Ciphertext), s.identity)
	if err != nil {
		log.Printf("Failed to decrypt: %s", err)
		return nil, err
	}

	plaintext := &bytes.Buffer{}
	if _, err := io.Copy(plaintext, r); err != nil {
		log.Printf("Failed to decrypt: %s", err)
		return nil, err
	}

	return plaintext.Bytes(), nil
}

func main() {
	var (
		identityPath   = flag.String("identity", "./identity", "identity file")
		recipientsPath = flag.String("recipients", "./recipients", "recipients file")
		socketPath     = flag.String("socket", "/var/run/age-kms-plugin.sock", "socket path")
	)
	flag.Parse()

	identities, err := loadIdentities(identityPath)
	if err != nil {
		log.Panicf("Failed to load identities from %s: %s", *identityPath, err)
	}

	keyId, recipients, err := loadRecipients(recipientsPath)
	if err != nil {
		log.Panicf("Failed to load recipients from %s: %s", *recipientsPath, err)
	}

	log.Printf("Loaded %d recipients, key ID: %s", len(recipients), keyId)

	os.Remove(*socketPath)

	s := &server{
		keyId:      keyId,
		identity:   identities[0],
		recipients: recipients,
	}
	svc := kms.NewGRPCService(*socketPath, 10*time.Second, s)
	defer svc.Shutdown()

	log.Printf("Listening on %s", *socketPath)
	svc.ListenAndServe()
}

func loadRecipients(recipientsPath *string) (string, []age.Recipient, error) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()

	f, err := os.Open(*recipientsPath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	d, err := hashFile(f)
	if err != nil {
		return "", nil, err
	}

	keyId := hex.EncodeToString(d)

	log.Print("Recipients file contents:")
	f.Seek(0, 0)
	io.Copy(stdoutDumper, f)

	f.Seek(0, 0)
	recipients, err := age.ParseRecipients(f)
	if err != nil {
		return "", nil, err
	}

	return keyId, recipients, nil
}

func loadIdentities(identityPath *string) ([]age.Identity, error) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()

	f, err := os.Open(*identityPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	log.Print("Identities file contents:")
	io.Copy(stdoutDumper, f)

	f.Seek(0, 0)
	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, err
	}

	return identities, nil
}

func hashFile(file io.Reader) ([]byte, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}
