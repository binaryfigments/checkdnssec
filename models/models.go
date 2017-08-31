package checkdnssec

import "time"

/*
 * Used Models
 */

// Message struct for returning the question and the answer.
type Message struct {
	Question Question `json:"question"`
	Answer   Answer   `json:"answer"`
}

// Question struct for retuning what information is asked.
type Question struct {
	JobDomain  string    `json:"domain"`
	JobStatus  string    `json:"status"`
	JobMessage string    `json:"message"`
	JobTime    time.Time `json:"time"`
}

// Answer struct the answer of the question.
type Answer struct {
	Registry          Registry        `json:"tld,omitempty"`
	Nameservers       Nameservers     `json:"nameservers,omitempty"`
	DSRecordCount     int             `json:"dsrecordcount,omitempty"`
	DNSKEYRecordCount int             `json:"dnskeyrecordcount,omitempty"`
	DSRecords         []*DomainDS     `json:"dsrecords,omitempty"`
	DNSKEYRecords     []*DomainDNSKEY `json:"dnskeyrecords,omitempty"`
	CalculatedDS      []*DomainDS     `json:"calculatedds,omitempty"`
	Matching          Matching        `json:"matching,omitempty"`
}

// Matching struct for information
type Matching struct {
	DS     []*DomainDS     `json:"ds,omitempty"`
	DNSKEY []*DomainDNSKEY `json:"dnskey,omitempty"`
}

// Registry struct for information
type Registry struct {
	TLD   string `json:"tld,omitempty"`
	ICANN bool   `json:"icann,omitempty"`
}

// Nameservers struct for information
type Nameservers struct {
	Root     []string `json:"root,omitempty"`
	Registry []string `json:"registry,omitempty"`
	Domain   []string `json:"domain,omitempty"`
}

// DomainDS struct
type DomainDS struct {
	Algorithm  uint8  `json:"algorithm,omitempty"`
	Digest     string `json:"digest,omitempty"`
	DigestType uint8  `json:"digesttype,omitempty"`
	KeyTag     uint16 `json:"keytag,omitempty"`
}

// DomainDNSKEY struct
type DomainDNSKEY struct {
	Algorithm    uint8     `json:"algorithm,omitempty"`
	Flags        uint16    `json:"flags,omitempty"`
	Protocol     uint8     `json:"protocol,omitempty"`
	PublicKey    string    `json:"publickey,omitempty"`
	CalculatedDS *DomainDS `json:"calculatedds,omitempty"`
}
