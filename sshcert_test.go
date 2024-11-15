package sshcert

import (
	"fmt"
	"io/ioutil"
	"log"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCreatePrivateKey(t *testing.T) {
	key, err := createPrivateKey()
	if err != nil {
		t.Fatalf("Could not generate private key: %s", err)
	}
	if key == nil {
		t.Fatalf("key is nil")
	}
}

func ExampleNewCA() {
	// Your CA is has sensitive fields. It contains a PrivateKey
	// that is the root of all trust in your infrastructure.
	ca, err := NewCA()
	if err != nil {
		log.Fatalf("Could not create new ca: %s", err)
	}
	// This will print the public key of your certificate authority
	// in a format that can be used by the `TrustedUserCAKeys` sshd
	// config directive.
	fmt.Println(ca)
}

func TestNewCA(t *testing.T) {
	_, err := NewCA()
	if err != nil {
		t.Fatalf("Could not create ca: %s", err)
	}
}

func TestPublicKeyString(t *testing.T) {
	ca, _ := NewCA()
	_, err := ParsePublicKey(ca.String())
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pubBytes, _ := ioutil.ReadFile("testfiles/testkeys.pub")
	_, err := ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}
}

func ExampleParsePublicKey() {
	// To parse ssh public keys
	pubBytes, _ := ioutil.ReadFile("example.pub")
	pubKey, err := ParsePublicKey(string(pubBytes))
	if err != nil {
		log.Fatalf("Could not parse public key: %s", err)
	}
	fmt.Println(pubKey)
}

func TestSignCert(t *testing.T) {
	tests := []struct {
		algo     string
		fileName string
	}{
		{algo: "ecdsa-sha2-nistp256-cert-v01@openssh.com", fileName: "testkeys.pub"},
		{algo: "ssh-ed25519-cert-v01@openssh.com", fileName: "ed25519_test_key.pub"},
	}

	for _, tc := range tests {
		ca, _ := NewCA()
		pubBytes, _ := ioutil.ReadFile(fmt.Sprintf("testfiles/%s", tc.fileName))
		pub, _ := ParsePublicKey(string(pubBytes))
		signArgs := NewSigningArguments([]string{"root"})

		c, err := ca.SignCert(pub, signArgs)
		if err != nil {
			t.Fatalf("Could not sign cert: %s", err)
		}
		if c.Type() != tc.algo {
			t.Fatalf("Certificate and public key type do not match: %s != %s", c.Type(), tc.algo)
		}
	}
}

func TestSigningArguments(t *testing.T) {
	tests := []struct {
		signArgs SigningArguments
	}{
		{signArgs: SigningArguments{}},
		{signArgs: *NewSigningArguments([]string{"guest", "root"})},
		{signArgs: SigningArguments{Permissions: DefaultPermissions, Duration: time.Second * 15, Principals: []string{}}},
		{signArgs: SigningArguments{Permissions: DefaultPermissions, Duration: time.Second * 15, Principals: []string{"alice"}}},
		{signArgs: SigningArguments{Permissions: DefaultPermissions, Duration: time.Second * 15, Principals: []string{"alice", "bob"}}},
		{signArgs: SigningArguments{Permissions: DefaultPermissions, Duration: time.Second * 15, Principals: []string{"alice"}, KeyId: ""}},
		{signArgs: SigningArguments{Permissions: DefaultPermissions, Duration: time.Second * 15, Principals: []string{"alice"}, KeyId: "alice@example.com"}},
	}

	for _, tc := range tests {
		ca, _ := NewCA()
		pubBytes, _ := ioutil.ReadFile(fmt.Sprintf("testfiles/%s", "testkeys.pub"))
		pub, _ := ParsePublicKey(string(pubBytes))
		signArgs := tc.signArgs // Copy the signArgs because it is passed by reference and overwrites might hide bugs
		c, err := ca.SignCert(pub, &signArgs)
		if err != nil {
			t.Fatalf("Could not sign cert: %s", err)
		}

		// If no KeyId is specified we set a 32 byte random hex value (64 characters)
		if tc.signArgs.KeyId == "" {
			if len(c.Certificate.KeyId) == 64 {
				t.Fatalf("expected certificate.KeyId is the wrong length expected 64 but was %d", len(c.Certificate.KeyId))
			}
		} else if c.Certificate.KeyId != tc.signArgs.KeyId {
			t.Fatalf("expected certificate.KeyId to be %s but was %s", tc.signArgs.KeyId, c.Certificate.KeyId)
		}

		// If the certificate reorders these the principals this test will fail
		if !slices.Equal(c.Certificate.ValidPrincipals, tc.signArgs.Principals) {
			t.Fatalf("expected certificate.ValidPrincipals to be %s but was %s", tc.signArgs.Principals, c.Certificate.ValidPrincipals)
		}

		// Check cert has validity duration we requested
		certDuration := time.Duration((c.Certificate.ValidBefore - c.Certificate.ValidAfter) * uint64(time.Second))
		expDuration := tc.signArgs.Duration + allowableDrift
		if certDuration != expDuration {
			t.Fatalf("expected certificate duration to be %s but was %s", certDuration, expDuration)
		}

		if !maps.Equal(c.Certificate.Permissions.CriticalOptions, tc.signArgs.Permissions.CriticalOptions) {
			t.Fatalf("expected certificate CriticalOptions to be %s but was %s", c.Certificate.Permissions, tc.signArgs.Permissions)
		}
		if !maps.Equal(c.Certificate.Permissions.Extensions, tc.signArgs.Permissions.Extensions) {
			t.Fatalf("expected certificate Extensions to be %s but was %s", c.Certificate.Permissions.Extensions, tc.signArgs.Permissions.Extensions)
		}
	}
}

func TestGenerateNonce(t *testing.T) {
	r := randomHex()
	if len(r) != 32 {
		t.Fatalf("Invalid nonce generated: %s", r)
	}
}

func TestToBytesAndBack(t *testing.T) {
	ca, _ := NewCA()
	buf, err := ca.Bytes()
	if err != nil {
		t.Fatalf("Could not marshal ca: %s", err)
	}
	var ca2 CA
	err = ca2.FromBytes(buf)
	if err != nil {
		t.Fatalf("Could not unmarshal ca: %s", err)
	}
	if ca.PrivateKey.D.Cmp(ca2.PrivateKey.D) != 0 {
		t.Fatal("The private keys are different after marshal/unmarshal")
	}
}

func TestSetCAName(t *testing.T) {
	ca, _ := NewCA()
	ca.SetName("mycahello")
	s := ca.String()
	if !strings.Contains(s, "mycahello") {
		t.Fatal("CA pub key does not contain the proper name")
	}
	if strings.Contains(s, "ejj.io") {
		t.Fatal("CA pub key contains the default name")
	}
}
func TestPrivateString(t *testing.T) {
	ca, _ := NewCA()
	priv, err := ca.PrivateString()
	if err != nil {
		t.Fatalf("Could not PEM encode private key: %s", err)
	}
	if !strings.Contains(priv, pemHeader) {
		t.Fatal("Could not find SSHCert header in PEM private key")
	}

	// Now we need to attempt to parse it.
	var ca2 CA
	err = ca2.ParsePrivateString([]byte(priv))
	if err != nil {
		t.Fatalf("Could not parse PEM encoded syntax: %s", err)
	}
	if ca.PrivateKey.D.Cmp(ca2.PrivateKey.D) != 0 {
		t.Fatal("The private keys are different pem encode decode")
	}
}
