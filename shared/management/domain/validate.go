package domain

import (
	"fmt"
	"strings"
)

const maxDomains = 32

// IsValidDomain checks if a single domain string is valid.
// Does not convert unicode to punycode - domain must already be ASCII/punycode.
// Allows wildcard prefix (*.example.com).
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return isValidDomainName(strings.ToLower(domain), true)
}

// IsValidDomainNoWildcard checks if a single domain string is valid without wildcard prefix.
// Use for zone domains and CNAME targets where wildcards are not allowed.
func IsValidDomainNoWildcard(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.HasPrefix(domain, "*.") {
		return false
	}
	return isValidDomainName(strings.ToLower(domain), false)
}

// ValidateDomains validates domains and converts unicode to punycode.
// Allows wildcard prefix (*.example.com). Maximum 32 domains.
func ValidateDomains(domains []string) (List, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list is empty")
	}
	if len(domains) > maxDomains {
		return nil, fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	var domainList List

	for _, d := range domains {
		// handles length and idna conversion
		punycode, err := FromString(d)
		if err != nil {
			return domainList, fmt.Errorf("convert domain to punycode: %s: %w", d, err)
		}

		if !isValidDomainName(string(punycode), true) {
			return domainList, fmt.Errorf("invalid domain format: %s", d)
		}

		domainList = append(domainList, punycode)
	}
	return domainList, nil
}

// ValidateDomainsList validates domains without punycode conversion.
// Use this for domains that must already be in ASCII/punycode format (e.g., extra DNS labels).
// Unlike ValidateDomains, this does not convert unicode to punycode - unicode domains will fail.
// Allows wildcard prefix (*.example.com). Maximum 32 domains.
func ValidateDomainsList(domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	if len(domains) > maxDomains {
		return fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	for _, d := range domains {
		d := strings.ToLower(d)
		if !isValidDomainName(d, true) {
			return fmt.Errorf("invalid domain format: %s", d)
		}
	}
	return nil
}

func isValidDomainName(domain string, allowWildcard bool) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	if strings.HasPrefix(domain, "*.") {
		if !allowWildcard {
			return false
		}
		domain = strings.TrimPrefix(domain, "*.")
		if domain == "" {
			return false
		}
	} else if strings.Contains(domain, "*") {
		return false
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if !isValidDomainLabel(label) {
			return false
		}
	}
	return true
}

func isValidDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
