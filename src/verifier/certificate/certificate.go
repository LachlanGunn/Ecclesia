package certificate

import (
	"crypto/tls"
	"crypto/x509"
)

func GetCertificate(address string, novalidate bool) (*x509.Certificate, error)  {
	connection, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: novalidate,
	})
	defer func(){ if connection != nil { connection.Close() } }()
	if err != nil {
		return nil, err
	}

	certificate := connection.ConnectionState().PeerCertificates[0]
	return certificate, nil
}
