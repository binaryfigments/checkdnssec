package checkdnssec

import (
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/binaryfigments/checkdnssec/models"
)

// Run function
func Run(domain string, startnameserver string) (*checkdnssec.Message, error) {
	msg := new(checkdnssec.Message)
	msg.Question.JobTime = time.Now()

	// Valid domain name (ASCII or IDN)
	domain, err := idna.ToASCII(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Non ASCII or IDN characters in domain."
		return msg, err
	}

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Domain not OK"
		return msg, err
	}

	msg.Question.JobDomain = domain

	// Go check DNS!

	domainstate := checkDomainState(domain)
	if domainstate != "OK" {
		// log.Println(domainstate)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = domainstate
		return msg, err
	}

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	msg.Answer.Registry.TLD = tld
	msg.Answer.Registry.ICANN = tldicann

	// Root nameservers
	rootNameservers, err := resolveDomainNS(".", startnameserver)
	if err != nil {
		// log.Println("No nameservers found: .", err)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Root = rootNameservers

	// TLD nameserver
	registryNameservers, err := resolveDomainNS(tld, startnameserver)
	if err != nil {
		// log.Println("No nameservers found: .", err)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Registry = registryNameservers
	registryNameserver := registryNameservers[0]

	// Domain nameservers at zone
	domainNameservers, err := resolveDomainNS(domain, startnameserver)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Domain = domainNameservers
	domainNameserver := domainNameservers[0]

	/*
	 * DS and DNSKEY information
	 */

	// Domain nameservers at Hoster
	domainds, err := resolveDomainDS(domain, registryNameserver)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error DS lookup"
		return msg, err
	}
	msg.Answer.DSRecords = domainds
	msg.Answer.DSRecordCount = cap(domainds)

	dnskey, err := resolveDomainDNSKEY(domain, domainNameserver)
	if err != nil {
		// log.Println("DNSKEY lookup failed: .", err)
	}
	// log.Println("[OK] DNSKEY record lookup done.")

	msg.Answer.DNSKEYRecords = dnskey
	msg.Answer.DNSKEYRecordCount = cap(msg.Answer.DNSKEYRecords)

	var digest uint8
	if cap(msg.Answer.DSRecords) != 0 {
		digest = msg.Answer.DSRecords[0].DigestType
		// log.Println("[OK] DS digest type found:", digest)
	}

	if msg.Answer.DSRecordCount > 0 && msg.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, domainNameserver)
		if err != nil {
			// log.Println("[ERROR] DS calc failed: .", err)
		}
		msg.Answer.CalculatedDS = calculatedDS
	}

	if msg.Answer.DSRecordCount > 0 && msg.Answer.DNSKEYRecordCount > 0 {
		filtered := []*checkdnssec.DomainDS{}
		dnskeys := []*checkdnssec.DomainDNSKEY{}
		keydex := 0
		for _, e := range msg.Answer.DSRecords {
			for _, f := range msg.Answer.CalculatedDS {
				if f.Digest == e.Digest {
					filtered = append(filtered, f)
					dnskeys = append(dnskeys, msg.Answer.DNSKEYRecords[keydex])
				}
				keydex++
			}
		}
		msg.Answer.Matching.DS = filtered
		msg.Answer.Matching.DNSKEY = dnskeys
	}

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveDomainNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, a.Ns)
		}
	}
	return answer, nil
}

func resolveDomainDS(domain string, nameserver string) ([]*checkdnssec.DomainDS, error) {
	ds := []*checkdnssec.DomainDS{}
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		// log.Println("[FAIL] No DS records found.")
		return ds, err
	}
	// fmt.Println(cap(in.Answer))
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DS); ok {
			readkey := new(checkdnssec.DomainDS)
			readkey.Algorithm = a.Algorithm
			readkey.Digest = a.Digest
			readkey.DigestType = a.DigestType
			readkey.KeyTag = a.KeyTag
			ds = append(ds, readkey)
		}
	}
	return ds, nil
}

func resolveDomainDNSKEY(domain string, nameserver string) ([]*checkdnssec.DomainDNSKEY, error) {
	dnskey := []*checkdnssec.DomainDNSKEY{}

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return dnskey, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			readkey := new(checkdnssec.DomainDNSKEY)
			readkey.Algorithm = a.Algorithm
			readkey.Flags = a.Flags
			readkey.Protocol = a.Protocol
			readkey.PublicKey = a.PublicKey
			dnskey = append(dnskey, readkey)
		}
	}
	return dnskey, err
}

/*
 * calculateDSRecord function for generating DS records from the DNSKEY.
 * Input: domainname, digest and nameserver from the hoster.
 * Output: one of more structs with DS information
 */

func calculateDSRecord(domain string, digest uint8, nameserver string) ([]*checkdnssec.DomainDS, error) {
	calculatedDS := []*checkdnssec.DomainDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return calculatedDS, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			calckey := new(checkdnssec.DomainDS)
			calckey.Algorithm = a.ToDS(digest).Algorithm
			calckey.Digest = a.ToDS(digest).Digest
			calckey.DigestType = a.ToDS(digest).DigestType
			calckey.KeyTag = a.ToDS(digest).KeyTag
			calculatedDS = append(calculatedDS, calckey)
		}
	}
	return calculatedDS, nil
}

// checkDomainState
func checkDomainState(domain string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

Redo:
	in, _, err := c.Exchange(m, "8.8.8.8:53")

	if err == nil {
		switch in.MsgHdr.Rcode {
		case dns.RcodeServerFailure:
			return "500, 502, The name server encountered an internal failure while processing this request (SERVFAIL)"
		case dns.RcodeNameError:
			return "500, 503, Some name that ought to exist, does not exist (NXDOMAIN)"
		case dns.RcodeRefused:
			return "500, 505, The name server refuses to perform the specified operation for policy or security reasons (REFUSED)"
		default:
			return "OK"
		}
	} else if err == dns.ErrTruncated {
		c.Net = "tcp"
		goto Redo
	} else {
		return "500, 501, DNS server could not be reached"
	}
}
