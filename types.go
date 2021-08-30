package soapclient

import (
	"encoding/xml"
	"log"
)

type envelope struct {
	XMLName xml.Name    `xml:"soap-env:Envelope"`
	Header  *header     `xml:"soap-env:Header"`
	Text    string      `xml:",chardata"`
	Soapenv string      `xml:"xmlns:soap-env,attr"`
	V1      string      `xml:"xmlns:v1,attr"`
	Body    interface{} `xml:"soap-env:Body"`
}

type header struct {
	XMLName  xml.Name        `xml:"soap-env:Header"`
	Text     string          `xml:",chardata"`
	Security *headerSecurity `xml:"wsse:Security"`
}

type headerSecurity struct {
	XMLName xml.Name `xml:"wsse:Security"`
	Text    string   `xml:",chardata"`
	Wsse    string   `xml:"xmlns:wsse,attr"`

	Signature     *headerSecuritySignature     `xml:"Signature"`
	UsernameToken *headerSecurityUsernameToken `xml:"wsse:UsernameToken"`
}

type headerSecurityUsernameToken struct {
	Text     string                               `xml:",chardata"`
	Username string                               `xml:"wsse:Username"`
	Password *headerSecurityUsernameTokenPassword `xml:"wsse:Password"`
}

type headerSecurityUsernameTokenPassword struct {
	Text string `xml:",chardata"`
	Type string `xml:"Type,attr"`
}

type headerSecuritySignature struct {
	Text           string                             `xml:",chardata"`
	ID             string                             `xml:"Id,attr"`
	Xmlns          string                             `xml:"xmlns,attr"`
	SignedInfo     *headerSecuritySignatureSignedInfo `xml:"SignedInfo"`
	SignatureValue string                             `xml:"SignatureValue"`
	KeyInfo        *headerSecuritySignatureKeyInfo    `xml:"KeyInfo"`
}

type headerSecuritySignatureSignedInfo struct {
	Text                   string                  `xml:",chardata"`
	CanonicalizationMethod *canonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        *signatureMethod        `xml:"SignatureMethod"`
	DsReference            *reference              `xml:"Reference"`
}

type canonicalizationMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type signatureMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type reference struct {
	Text         string        `xml:",chardata"`
	URI          string        `xml:"URI,attr"`
	Transforms   *transforms   `xml:"Transforms"`
	DigestMethod *digestMethod `xml:"DigestMethod"`
	DigestValue  string        `xml:"DigestValue"`
}

type transforms struct {
	Text      string     `xml:",chardata"`
	Transform *transform `xml:"Transform"`
}

type transform struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type digestMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type headerSecuritySignatureKeyInfo struct {
	Text                   string                        `xml:",chardata"`
	ID                     string                        `xml:"Id,attr"`
	SecurityTokenReference keyInfoSecurityTokenReference `xml:"wsse:SecurityTokenReference"`
}

type keyInfoSecurityTokenReference struct {
	Text     string   `xml:",chardata"`
	X509Data x509Data `xml:"X509Data"`
}

type x509Data struct {
	Text             string           `xml:",chardata"`
	X509IssuerSerial x509IssuerSerial `xml:"X509IssuerSerial"`
	X509Certificate  x509Certificate  `xml:"X509Certificate"`
}

type x509Certificate struct {
	Text string `xml:",chardata"`
}

type x509IssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber string `xml:"X509SerialNumber"`
}

type requestBody struct {
	XMLName   xml.Name `xml:"soap-env:Body"`
	Text      string   `xml:",chardata"`
	ID        string   `xml:"ns1:ID,attr"`
	NS        string   `xml:"xmlns:soap-env,attr"`
	Wsu       string   `xml:"xmlns:ns1,attr"`
	Operation Operation
}

// Operation defines an operation for the SOAP service
type Operation struct {
	// Name is the name of the operation. It is mandatory.
	Name string
	// Data receives the data/body of the request for the operation. Mandatory.
	Data map[string]interface{}
	// Validate runs a validation of the signature before sending the request. Use it only for development
	Validate bool
}

func xmlTokensFor(i interface{}) []xml.Token {
	tokens := []xml.Token{}

	switch v := i.(type) {
	case string:
		tokens = append(tokens, xml.CharData(v))
	case map[string]interface{}:
		eachSortedKeyValue(v, func(key string, value interface{}) {
			t := xml.StartElement{Name: xml.Name{Local: "v1:" + key}}

			tokens = append(tokens, t)
			tokens = append(tokens, xmlTokensFor(value)...)
			tokens = append(tokens, xml.EndElement{Name: t.Name})
		})
	default:
		log.Panicf("type %T not supported", i)
	}

	return tokens
}

// MarshalXML marshals the Operation in XML. The keys of the operation Data are always sorted alphabetically.
func (op Operation) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "v1:" + op.Name}
	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns:v1"}, Value: "http://ws.hc2.dc.com/v1"})

	tokens := []xml.Token{start}

	eachSortedKeyValue(op.Data, func(key string, value interface{}) {
		t := xml.StartElement{Name: xml.Name{Local: "v1:" + key}}

		tokens = append(tokens, t)
		tokens = append(tokens, xmlTokensFor(value)...)
		tokens = append(tokens, xml.EndElement{Name: t.Name})
	})

	tokens = append(tokens, xml.EndElement{Name: start.Name})

	for _, t := range tokens {
		err := e.EncodeToken(t)
		if err != nil {
			return err
		}
	}

	return e.Flush()
}
