package soapclient

import (
	"encoding/xml"
	"log"
)

type Envelope struct {
	XMLName xml.Name    `xml:"soap-env:Envelope"`
	Header  *Header     `xml:"soap-env:Header"`
	Text    string      `xml:",chardata"`
	Soapenv string      `xml:"xmlns:soap-env,attr"`
	V1      string      `xml:"xmlns:v1,attr"`
	Body    interface{} `xml:"soap-env:Body"`
}

type Header struct {
	XMLName  xml.Name        `xml:"soap-env:Header"`
	Text     string          `xml:",chardata"`
	Security *HeaderSecurity `xml:"wsse:Security"`
}

type HeaderSecurity struct {
	XMLName xml.Name `xml:"wsse:Security"`
	Text    string   `xml:",chardata"`
	Wsse    string   `xml:"xmlns:wsse,attr"`

	Signature     *HeaderSecuritySignature     `xml:"Signature"`
	UsernameToken *HeaderSecurityUsernameToken `xml:"wsse:UsernameToken"`
}

type HeaderSecurityUsernameToken struct {
	Text     string                               `xml:",chardata"`
	Username string                               `xml:"wsse:Username"`
	Password *HeaderSecurityUsernameTokenPassword `xml:"wsse:Password"`
}

type HeaderSecurityUsernameTokenPassword struct {
	Text string `xml:",chardata"`
	Type string `xml:"Type,attr"`
}

type HeaderSecuritySignature struct {
	Text           string                             `xml:",chardata"`
	ID             string                             `xml:"Id,attr"`
	Xmlns          string                             `xml:"xmlns,attr"`
	SignedInfo     *HeaderSecuritySignatureSignedInfo `xml:"SignedInfo"`
	SignatureValue string                             `xml:"SignatureValue"`
	KeyInfo        *HeaderSecuritySignatureKeyInfo    `xml:"KeyInfo"`
}

type HeaderSecuritySignatureSignedInfo struct {
	Text                   string                  `xml:",chardata"`
	CanonicalizationMethod *CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        *SignatureMethod        `xml:"SignatureMethod"`
	DsReference            *Reference              `xml:"Reference"`
}

type CanonicalizationMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type Reference struct {
	Text         string        `xml:",chardata"`
	URI          string        `xml:"URI,attr"`
	Transforms   *Transforms   `xml:"Transforms"`
	DigestMethod *DigestMethod `xml:"DigestMethod"`
	DigestValue  string        `xml:"DigestValue"`
}

type Transforms struct {
	Text      string     `xml:",chardata"`
	Transform *transform `xml:"Transform"`
}

type transform struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestMethod struct {
	Text      string `xml:",chardata"`
	Algorithm string `xml:"Algorithm,attr"`
}

type HeaderSecuritySignatureKeyInfo struct {
	Text                   string                        `xml:",chardata"`
	ID                     string                        `xml:"Id,attr"`
	SecurityTokenReference KeyInfoSecurityTokenReference `xml:"wsse:SecurityTokenReference"`
}

type KeyInfoSecurityTokenReference struct {
	Text     string   `xml:",chardata"`
	X509Data X509Data `xml:"X509Data"`
}

type X509Data struct {
	Text             string           `xml:",chardata"`
	X509IssuerSerial X509IssuerSerial `xml:"X509IssuerSerial"`
	X509Certificate  X509Certificate  `xml:"X509Certificate"`
}

type X509Certificate struct {
	Text string `xml:",chardata"`
}

type X509IssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber string `xml:"X509SerialNumber"`
}

type Body struct {
	XMLName   xml.Name `xml:"soap-env:Body"`
	Text      string   `xml:",chardata"`
	ID        string   `xml:"ns1:ID,attr"`
	NS        string   `xml:"xmlns:soap-env,attr"`
	Wsu       string   `xml:"xmlns:ns1,attr"`
	Operation Operation
}

type Operation struct {
	Name     string
	Data     map[string]interface{}
	Validate bool
	Verbose  bool
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
