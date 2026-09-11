// Package ocspcheck performs an RFC 6960 status check for one certificate.
//
// All cryptography is golang.org/x/crypto/ocsp. The only gap it leaves is the
// RFC 8954 nonce: CreateRequest emits no requestExtensions, and
// Response.Extensions exposes singleExtensions rather than the
// responseExtensions the nonce is echoed in. The helpers at the bottom fill
// exactly that gap, modelling everything around the nonce as asn1.RawValue so
// the CertID, status and signature pass through untouched.
package ocspcheck

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	// NonceLen is within the RFC 8954 range the rasenmaeher responder accepts.
	NonceLen = 16
	// MaxResponseBytes bounds a misbehaving responder. A single response is a
	// few hundred bytes.
	MaxResponseBytes = 64 << 10
	// ClockSkew tolerated when checking thisUpdate/nextUpdate.
	ClockSkew = 5 * time.Minute

	contentTypeRequest  = "application/ocsp-request"
	contentTypeResponse = "application/ocsp-response"
)

// oidNonce is id-pkix-ocsp-nonce (RFC 8954).
var oidNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// Checker queries one OCSP responder.
type Checker struct {
	URL    string
	Client *http.Client
}

// Check returns the responder's verdict for leaf, as issued by issuer.
func (c *Checker) Check(leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	if c == nil || c.URL == "" {
		return nil, errors.New("ocsp url is not configured")
	}
	if leaf == nil || issuer == nil {
		return nil, errors.New("leaf and issuer are both required")
	}

	// The responder accepts sha1 and sha256 issuer hashes.
	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("build ocsp request: %w", err)
	}

	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	reqDER, err = withNonce(reqDER, nonce)
	if err != nil {
		return nil, fmt.Errorf("attach nonce: %w", err)
	}

	body, err := c.post(reqDER)
	if err != nil {
		return nil, err
	}

	// Verifies the signature against the issuer and matches the serial.
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("parse ocsp response: %w", err)
	}
	if err := verifyNonce(body, nonce); err != nil {
		return nil, err
	}
	if err := checkFreshness(resp, time.Now()); err != nil {
		return nil, err
	}
	return resp, nil
}

// checkFreshness rejects a stale response; x/crypto parses the timestamps but
// never compares them to the clock.
func checkFreshness(resp *ocsp.Response, now time.Time) error {
	if !resp.ThisUpdate.IsZero() && resp.ThisUpdate.After(now.Add(ClockSkew)) {
		return fmt.Errorf("response thisUpdate %s is in the future", resp.ThisUpdate)
	}
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(now.Add(-ClockSkew)) {
		return fmt.Errorf("response expired at nextUpdate %s", resp.NextUpdate)
	}
	return nil
}

func (c *Checker) post(reqDER []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("build http request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeRequest)
	req.Header.Set("Accept", contentTypeResponse)

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return body, nil
}

// --- the only hand-written ASN.1 in this repo ---

type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version           int `asn1:"explicit,tag:0,default:0,optional"`
	RequestList       []asn1.RawValue
	RequestExtensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID     asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []asn1.RawValue
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// withNonce re-emits an OCSP request carrying the nonce extension.
func withNonce(reqDER, nonce []byte) ([]byte, error) {
	var parsed ocspRequest
	if _, err := asn1.Unmarshal(reqDER, &parsed); err != nil {
		return nil, fmt.Errorf("parse generated request: %w", err)
	}
	value, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("marshal nonce: %w", err)
	}
	parsed.TBSRequest.RequestExtensions = append(parsed.TBSRequest.RequestExtensions,
		pkix.Extension{Id: oidNonce, Value: value})

	out, err := asn1.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("re-marshal request: %w", err)
	}
	return out, nil
}

// verifyNonce requires the echo; the responder always sends one on success.
func verifyNonce(respDER, nonce []byte) error {
	var outer responseASN1
	if _, err := asn1.Unmarshal(respDER, &outer); err != nil {
		return fmt.Errorf("parse response envelope: %w", err)
	}
	var basic basicResponse
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		return fmt.Errorf("parse basic response: %w", err)
	}
	for _, ext := range basic.TBSResponseData.ResponseExtensions {
		if !ext.Id.Equal(oidNonce) {
			continue
		}
		var got []byte
		if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
			return fmt.Errorf("parse response nonce: %w", err)
		}
		if !bytes.Equal(nonce, got) {
			return errors.New("response nonce does not match the request nonce")
		}
		return nil
	}
	return errors.New("response does not echo the request nonce")
}
