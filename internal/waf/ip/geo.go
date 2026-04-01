package ip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"wafsrv/internal/waf"

	"github.com/oschwald/geoip2-golang"
)

type geoReader struct {
	country *geoip2.Reader
	asn     *geoip2.Reader
}

// newGeoReader opens GeoIP databases.
// If paths are provided, external files are used (override).
// If paths are empty, embedded databases are used as fallback.
func newGeoReader(countryPath, asnPath string) (*geoReader, error) {
	g := &geoReader{}

	var err error

	g.country, err = openOrEmbed(countryPath, embeddedCountryDB, "country")
	if err != nil {
		return nil, err
	}

	g.asn, err = openOrEmbed(asnPath, embeddedASNDB, "asn")
	if err != nil {
		if g.country != nil {
			g.country.Close()
		}

		return nil, err
	}

	return g, nil
}

func openOrEmbed(path string, embedded []byte, name string) (*geoip2.Reader, error) {
	if path != "" {
		r, err := geoip2.Open(path)
		if err != nil {
			return nil, fmt.Errorf("ip: open %s db %q: %w", name, path, err)
		}

		return r, nil
	}

	if len(embedded) > 0 {
		r, err := geoip2.FromBytes(embedded)
		if err != nil {
			return nil, fmt.Errorf("ip: load embedded %s db: %w", name, err)
		}

		return r, nil
	}

	return nil, nil
}

func (g *geoReader) close() error {
	var errs []error

	if g.country != nil {
		if err := g.country.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if g.asn != nil {
		if err := g.asn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (g *geoReader) lookup(addr netip.Addr, info *waf.IPInfo) {
	a16 := addr.As16()
	ip := net.IP(a16[:])

	if addr.Is4() {
		a4 := addr.As4()
		ip = net.IP(a4[:])
	}

	if g.country != nil {
		if rec, err := g.country.Country(ip); err == nil {
			info.Country = rec.Country.IsoCode
		}
	}

	if g.asn != nil {
		if rec, err := g.asn.ASN(ip); err == nil {
			info.ASN = uint32(rec.AutonomousSystemNumber)
			info.ASNOrg = rec.AutonomousSystemOrganization
		}
	}
}
