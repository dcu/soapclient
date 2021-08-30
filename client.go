package soapclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/beevik/etree"
	"github.com/ma314smith/signedxml"
)

type Client struct {
	url        string
	opts       ClientOpts
	httpClient *http.Client
}

type ClientOpts struct {
	Certificate tls.Certificate
	Username    string
	Password    string
}

func (opts ClientOpts) validate() {
	if len(opts.Certificate.Certificate) == 0 {
		panic("client Certificate is required")
	}
}

func (opts ClientOpts) getHTTPClient() *http.Client {
	client := &http.Client{}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{
				opts.Certificate,
			},
		},
	}

	return client
}

func (opts ClientOpts) getCertInfo() (string, string) {
	pCert, err := x509.ParseCertificate(opts.Certificate.Certificate[0])
	if err != nil {
		panic(err)
	}

	return pCert.Issuer.String(), pCert.SerialNumber.String()
}

// New creates a new Client. This client is supposed to be shared between threads
func New(url string, opts ClientOpts) *Client {
	opts.validate()

	return &Client{
		url:        url,
		opts:       opts,
		httpClient: opts.getHTTPClient(),
	}
}

// BuildEnvelope builds the envelope for the request
func (c *Client) BuildEnvelope(op Operation) *Envelope {
	body := Body{
		Operation: op,
		NS:        "http://schemas.xmlsoap.org/soap/envelope/",
		ID:        generateID("id"),
		Wsu:       "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	}

	signInfo := &HeaderSecuritySignatureSignedInfo{
		CanonicalizationMethod: &CanonicalizationMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: &SignatureMethod{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		},
		DsReference: &Reference{
			URI:         "#" + body.ID,
			DigestValue: "",
			DigestMethod: &DigestMethod{
				Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
			},
			Transforms: &Transforms{
				Transform: &transform{
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
			},
		},
	}

	certIssuerName, certSerialNumber := c.opts.getCertInfo()
	reqHeader := &Header{
		XMLName: xml.Name{},
		Security: &HeaderSecurity{
			Wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
			UsernameToken: &HeaderSecurityUsernameToken{
				Username: c.opts.Username,
				Password: &HeaderSecurityUsernameTokenPassword{
					Type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText",
					Text: c.opts.Password,
				},
			},
			Signature: &HeaderSecuritySignature{
				ID:             generateID("SIG"),
				Xmlns:          "http://www.w3.org/2000/09/xmldsig#",
				SignatureValue: "",
				SignedInfo:     signInfo,
				KeyInfo: &HeaderSecuritySignatureKeyInfo{
					ID: generateID("KI"),
					SecurityTokenReference: KeyInfoSecurityTokenReference{
						X509Data: X509Data{
							X509IssuerSerial: X509IssuerSerial{
								X509IssuerName:   certIssuerName,
								X509SerialNumber: certSerialNumber,
							},
							X509Certificate: X509Certificate{Text: base64.StdEncoding.EncodeToString(c.opts.Certificate.Certificate[0])},
						},
					},
				},
			},
		},
	}

	envelope := &Envelope{
		Soapenv: "http://schemas.xmlsoap.org/soap/envelope/",
		V1:      "http://ws.hc2.dc.com/v1",
		Body:    body,
		Header:  reqHeader,
	}

	return envelope
}

// RawQuery does a query and returns the response
func (c *Client) RawQuery(op Operation) ([]byte, error) {
	envelope := c.BuildEnvelope(op)

	xmlBytes, err := xml.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	signer, err := signedxml.NewSigner(string(xmlBytes))
	if err != nil {
		return nil, err
	}

	signedXML, err := signer.Sign(c.opts.Certificate.PrivateKey)
	if err != nil {
		return nil, err
	}

	if op.Validate {
		validator, err := signedxml.NewValidator(signedXML)
		if err != nil {
			panic(err)
		}

		_, err = validator.ValidateReferences()
		if err != nil {
			return nil, fmt.Errorf("error validating: %w", err)
		}
	}

	if op.Verbose {
		log.Printf("REQUEST: %s", signedXML)
	}

	req, err := http.NewRequest("POST", c.url, strings.NewReader(signedXML))
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	data, err := ioutil.ReadAll(response.Body)

	if op.Verbose {
		log.Println("RESPONSE:", string(data))
	}

	return data, err
}

// Query performs the query and returns a *etree.Document
func (c *Client) Query(op Operation) (*etree.Document, error) {
	res, err := c.RawQuery(op)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	doc.ReadFromBytes(res)

	return doc, nil
}
