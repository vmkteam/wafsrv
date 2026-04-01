package ip

import _ "embed"

// Embedded GeoIP databases (db-ip.com lite, free).
// Override with external files via Config.GeoDatabase / Config.ASNDatabase.

//go:embed data/dbip-country-lite.mmdb
var embeddedCountryDB []byte

//go:embed data/dbip-asn-lite.mmdb
var embeddedASNDB []byte
