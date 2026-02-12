package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser implements the lego registration.User interface.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMEIssuer issues TLS certificates via ACME DNS-01 challenge (Route53).
type ACMEIssuer struct {
	client *lego.Client
}

// NewACMEIssuer creates an ACMEIssuer configured for DNS-01 challenge.
// When dnsProvider is nil, Route53 is used (credentials from AWS env vars).
// When dnsProvider is non-nil, the provided DNS challenge provider is used
// along with any additional challenge options (e.g., for test environments).
func NewACMEIssuer(email, acmeDirectory string, dnsProvider challenge.Provider, challengeOpts ...dns01.ChallengeOption) (*ACMEIssuer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ACME account key: %w", err)
	}

	user := &acmeUser{
		email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = acmeDirectory
	config.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating ACME client: %w", err)
	}

	if dnsProvider == nil {
		provider, err := route53.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("creating Route53 DNS provider: %w", err)
		}
		dnsProvider = provider
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider, challengeOpts...); err != nil {
		return nil, fmt.Errorf("setting DNS-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering ACME account: %w", err)
	}
	user.registration = reg

	return &ACMEIssuer{client: client}, nil
}

// Issue obtains a certificate for the given domain via DNS-01 challenge.
func (a *ACMEIssuer) Issue(_ context.Context, domain string) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := a.client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("obtaining certificate for %s: %w", domain, err)
	}

	// Parse the certificate to get NotAfter
	parsed, err := certcrypto.ParsePEMCertificate(certificates.Certificate)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("parsing issued certificate: %w", err)
	}

	return certificates.Certificate, certificates.PrivateKey, parsed.NotAfter, nil
}
