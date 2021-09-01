package soapclient

import "github.com/beevik/etree"

// ClientIface defines the interface for a SOAP Client. It makes mocking the client easier in your tests
type ClientIface interface {
	ListOperations() ([]string, error)
	RawQuery(op Operation) ([]byte, error)
	Query(op Operation) (*etree.Document, error)
}
