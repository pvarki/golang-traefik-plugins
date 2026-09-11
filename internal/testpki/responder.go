package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OIDNonce is id-pkix-ocsp-nonce (RFC 8954).
var OIDNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

var oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// ResponderOpts bends one aspect of an otherwise valid response.
type ResponderOpts struct {
	Status     int
	Nonce      []byte // override the echoed nonce
	OmitNonce  bool
	SignKey    *ecdsa.PrivateKey // defaults to the CA key
	NextUpdate time.Time
}

// Respond answers an OCSP request the way the rasenmaeher responder does,
// echoing the nonce in responseExtensions rather than singleExtensions.
//
// The singleResponse comes from x/crypto and is carried over verbatim as a raw
// value, so this never models the CertID or the certificate status.
func (ca *CA) Respond(t *testing.T, reqDER []byte, opts ResponderOpts) []byte {
	t.Helper()

	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("responder could not parse request: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	nextUpdate := opts.NextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = now.Add(time.Hour)
	}
	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber, Status: opts.Status,
		ThisUpdate: now.Add(-time.Minute), NextUpdate: nextUpdate,
		IssuerHash: crypto.SHA256,
	}
	if opts.Status == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-10 * time.Minute)
		tmpl.RevocationReason = ocsp.PrivilegeWithdrawn
	}
	inner, err := ocsp.CreateResponse(ca.Cert, ca.Cert, tmpl, ca.Key)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}

	var outer responseASN1
	if _, err := asn1.Unmarshal(inner, &outer); err != nil {
		t.Fatalf("unwrap generated response: %v", err)
	}
	var basic basicResponse
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		t.Fatalf("unwrap basic response: %v", err)
	}

	tbs := responseData{
		RawResponderID: basic.TBSResponseData.RawResponderID,
		ProducedAt:     now,
		Responses:      basic.TBSResponseData.Responses,
	}
	if !opts.OmitNonce {
		nonce := opts.Nonce
		if nonce == nil {
			nonce = RequestNonce(t, reqDER)
		}
		if nonce != nil {
			value, err := asn1.Marshal(nonce)
			if err != nil {
				t.Fatalf("marshal nonce: %v", err)
			}
			tbs.ResponseExtensions = []pkix.Extension{{Id: OIDNonce, Value: value}}
		}
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbsResponseData: %v", err)
	}
	tbs.Raw = tbsDER

	signKey := opts.SignKey
	if signKey == nil {
		signKey = ca.Key
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	basicDER, err := asn1.Marshal(basicResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal basic response: %v", err)
	}
	out, err := asn1.Marshal(responseASN1{
		Status:   asn1.Enumerated(0),
		Response: responseBytes{ResponseType: oidBasicResponse, Response: basicDER},
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return out
}

// Serve starts a responder answering every request with opts.
func (ca *CA) Serve(t *testing.T, opts ResponderOpts) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 1024)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ca.Respond(t, body, opts))
	}))
	t.Cleanup(server.Close)
	return server
}

// RequestNonce extracts the nonce from an OCSP request, or nil.
func RequestNonce(t *testing.T, reqDER []byte) []byte {
	t.Helper()
	var parsed ocspRequest
	if _, err := asn1.Unmarshal(reqDER, &parsed); err != nil {
		t.Fatalf("parse request: %v", err)
	}
	for _, ext := range parsed.TBSRequest.RequestExtensions {
		if !ext.Id.Equal(OIDNonce) {
			continue
		}
		var nonce []byte
		if _, err := asn1.Unmarshal(ext.Value, &nonce); err != nil {
			t.Fatalf("parse request nonce: %v", err)
		}
		return nonce
	}
	return nil
}

// Minimal ASN.1 shapes, mirroring internal/ocspcheck. Everything around the
// nonce is a raw value so nothing else is remodelled.

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
