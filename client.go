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
	"github.com/dcu/signedxml"
)

type Client struct {
	url        string
	opts       ClientOpts
	httpClient *http.Client
}

// ClientOpts defines the possible options to pass to a client
type ClientOpts struct {
	// Certificate is the tls certificate. It is mandatory
	Certificate tls.Certificate

	// Username for the UsernameToken as defined in https://www.oasis-open.org/committees/download.php/13392/wss-v1.1-spec-pr-UsernameTokenProfile-01.htm#_Toc104276211
	Username string

	// Password for the UsernameToken as defined in https://www.oasis-open.org/committees/download.php/13392/wss-v1.1-spec-pr-UsernameTokenProfile-01.htm#_Toc104276211
	Password string

	// Debug enables the verbose mode which prints output of steps. Use it only for development
	Debug bool

	// V1 set the v1 namespace value for the operation
	V1 string
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

	if len(opts.V1) == 0 {
		opts.V1 = "http://ws.hc2.dc.com/v1"
	}

	return &Client{
		url:        url,
		opts:       opts,
		httpClient: opts.getHTTPClient(),
	}
}

// buildEnvelope builds the envelope for the request
func (c *Client) buildEnvelope(op Operation) *envelope {
	body := requestBody{
		Operation: op,
		NS:        "http://schemas.xmlsoap.org/soap/envelope/",
		ID:        generateID("id"),
		Wsu:       "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	}

	signInfo := &headerSecuritySignatureSignedInfo{
		CanonicalizationMethod: &canonicalizationMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: &signatureMethod{
			Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		},
		DsReference: &reference{
			URI:         "#" + body.ID,
			DigestValue: "",
			DigestMethod: &digestMethod{
				Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
			},
			Transforms: &transforms{
				Transform: &transform{
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
			},
		},
	}

	certIssuerName, certSerialNumber := c.opts.getCertInfo()
	reqHeader := &header{
		XMLName: xml.Name{},
		Security: &headerSecurity{
			Wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
			UsernameToken: &headerSecurityUsernameToken{
				Username: c.opts.Username,
				Password: &headerSecurityUsernameTokenPassword{
					Type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText",
					Text: c.opts.Password,
				},
			},
			Signature: &headerSecuritySignature{
				ID:             generateID("SIG"),
				Xmlns:          "http://www.w3.org/2000/09/xmldsig#",
				SignatureValue: "",
				SignedInfo:     signInfo,
				KeyInfo: &headerSecuritySignatureKeyInfo{
					ID: generateID("KI"),
					SecurityTokenReference: keyInfoSecurityTokenReference{
						X509Data: x509Data{
							X509IssuerSerial: x509IssuerSerial{
								X509IssuerName:   certIssuerName,
								X509SerialNumber: certSerialNumber,
							},
							X509Certificate: x509Certificate{Text: base64.StdEncoding.EncodeToString(c.opts.Certificate.Certificate[0])},
						},
					},
				},
			},
		},
	}

	envelope := &envelope{
		Soapenv: "http://schemas.xmlsoap.org/soap/envelope/",
		V1:      c.opts.V1,
		Body:    body,
		Header:  reqHeader,
	}

	return envelope
}

// ListOperations lists all supported operations by the service
func (c *Client) ListOperations() ([]string, error) {
	req, err := http.NewRequest("GET", c.url+"?wsdl", nil)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if c.opts.Debug {
		log.Printf("RESPONSE: %s", data)
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(data)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0)
	ops := doc.FindElements("//wsdl:binding/wsdl:operation")
	for _, op := range ops {
		result = append(result, op.SelectAttrValue("name", ""))
	}

	return result, nil
}

// RawQuery does a query and returns the response
func (c *Client) RawQuery(op Operation) ([]byte, error) {
	envelope := c.buildEnvelope(op)

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

	if c.opts.Debug {
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

	if c.opts.Debug {
		log.Println("RESPONSE:", string(data))
	}

	return data, err
}

// Query performs the query and returns a *etree.Document
func (c *Client) Query(op Operation) (*etree.Document, error) {
	if op.V1 == "" {
		op.V1 = c.opts.V1
	}

	res, err := c.RawQuery(op)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	doc.ReadFromBytes(res)

	return doc, nil
}

var _ ClientIface = &Client{}
