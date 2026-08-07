package normalize

import (
	"fmt"
	"regexp"
)

// mitsubishiCatalog parses MELSEC model names.
//
// Mitsubishi names a controller after its series letter and its performance
// number, then appends CPU. R08CPU is a MELSEC iQ-R with an 08 class CPU,
// Q03UDVCPU is a MELSEC-Q, and FX5U belongs to MELSEC iQ-F. Advisories are
// written against the series, so recovering the series letter is the useful part.
type mitsubishiCatalog struct{}

func init() { registerCatalogParser(mitsubishiCatalog{}) }

func (mitsubishiCatalog) Name() string { return "mitsubishi-catalog" }

var (
	melsecCPUPattern = regexp.MustCompile(`^([RQLF])([0-9]{2,3})([A-Z]*)CPU`)
	melsecFXPattern  = regexp.MustCompile(`^FX([0-9])([A-Z]+)`)
)

var melsecSeries = map[string]string{
	"R": "MELSEC iQ-R",
	"Q": "MELSEC-Q",
	"L": "MELSEC-L",
	"F": "MELSEC-F",
}

func (p mitsubishiCatalog) Parse(raw string) (CatalogResult, bool) {
	key := CatalogKey(raw)
	if len(key) < 4 {
		return CatalogResult{}, false
	}

	// The FX5 family is named differently from the rack based series, so it is
	// checked first.
	if matches := melsecFXPattern.FindStringSubmatch(key); matches != nil {
		generation, variant := matches[1], matches[2]
		family := "MELSEC-F"
		if generation == "5" {
			family = "MELSEC iQ-F"
		}
		return CatalogResult{
			Parser:     p.Name(),
			VendorID:   "mitsubishi-electric",
			Family:     family,
			Series:     family,
			Model:      "FX" + generation + variant,
			Normalized: "FX" + generation + variant,
			Confidence: 0.85,
			Explanation: fmt.Sprintf("FX%s marks the %s family, variant %s",
				generation, family, variant),
		}, true
	}

	matches := melsecCPUPattern.FindStringSubmatch(key)
	if matches == nil {
		return CatalogResult{}, false
	}
	letter, performance, variant := matches[1], matches[2], matches[3]
	family := melsecSeries[letter]

	return CatalogResult{
		Parser:     p.Name(),
		VendorID:   "mitsubishi-electric",
		Family:     family,
		Series:     family,
		Model:      letter + performance + variant + "CPU",
		Normalized: letter + performance + variant + "CPU",
		Confidence: 0.85,
		Explanation: fmt.Sprintf("series letter %s marks %s, performance class %s",
			letter, family, performance),
	}, true
}
