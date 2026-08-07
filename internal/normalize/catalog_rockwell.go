package normalize

import (
	"fmt"
	"regexp"
	"strings"
)

// rockwellCatalog parses Allen-Bradley catalog numbers.
//
// A Rockwell catalog number leads with a platform number: 1756 is ControlLogix,
// 1769 is CompactLogix, 2711P is PanelView Plus. For controllers the suffix then
// encodes the controller series that advisories are written against, so
// 1756-L71 is a ControlLogix 5570 while 1756-L81E is a 5580.
//
// The series table is deliberately scoped per platform and only contains
// mappings that are unambiguous. An L3 suffix means one series on a 1769 and a
// different one on a 5069, so a platform blind lookup would confidently produce
// the wrong series name. Where the series is not certain the parser reports the
// platform family only, which still narrows an advisory search without asserting
// something false.
type rockwellCatalog struct{}

func init() { registerCatalogParser(rockwellCatalog{}) }

func (rockwellCatalog) Name() string { return "rockwell-catalog" }

// rockwellPattern matches a four digit platform, an optional platform letter, and
// a module suffix.
var rockwellPattern = regexp.MustCompile(`^([125][0-9]{3})([A-Z]?)([0-9A-Z]{2,})$`)

var rockwellPlatforms = map[string]string{
	"1756":  "ControlLogix",
	"1769":  "CompactLogix",
	"1768":  "CompactLogix",
	"1789":  "SoftLogix",
	"1794":  "FLEX I/O",
	"1734":  "POINT I/O",
	"1738":  "ArmorPOINT I/O",
	"1732":  "ArmorBlock",
	"1746":  "SLC 500",
	"1747":  "SLC 500",
	"1761":  "MicroLogix",
	"1762":  "MicroLogix",
	"1763":  "MicroLogix",
	"1764":  "MicroLogix",
	"1766":  "MicroLogix",
	"1771":  "PLC-5 I/O",
	"1785":  "PLC-5",
	"1783":  "Stratix",
	"1715":  "Redundant I/O",
	"1719":  "Ex I/O",
	"2080":  "Micro800",
	"2085":  "Micro800 Expansion",
	"2711":  "PanelView",
	"2711P": "PanelView Plus",
	"5069":  "CompactLogix 5380",
	"5015":  "CompactLogix 5480",
	"5094":  "FLEX 5000",
}

// rockwellSeries maps a platform to the controller series implied by a suffix
// prefix. Only entries that hold unambiguously are listed.
var rockwellSeries = map[string]map[string]string{
	"1756": {
		"L6": "ControlLogix 5560",
		"L7": "ControlLogix 5570",
		"L8": "ControlLogix 5580",
	},
	"5069": {
		"L3": "CompactLogix 5380",
	},
}

func (p rockwellCatalog) Parse(raw string) (CatalogResult, bool) {
	key := CatalogKey(raw)
	if len(key) < 6 {
		return CatalogResult{}, false
	}

	matches := rockwellPattern.FindStringSubmatch(key)
	if matches == nil {
		return CatalogResult{}, false
	}
	platform, letter, suffix := matches[1], matches[2], matches[3]

	// PanelView Plus is 2711P, so the platform letter can be part of the
	// platform rather than the suffix.
	family, known := rockwellPlatforms[platform+letter]
	platformKey := platform + letter
	if !known {
		family, known = rockwellPlatforms[platform]
		if !known {
			return CatalogResult{}, false
		}
		platformKey = platform
		suffix = letter + suffix
	}

	result := CatalogResult{
		Parser:      p.Name(),
		VendorID:    "rockwell-automation",
		Family:      family,
		Series:      family,
		Normalized:  fmt.Sprintf("%s-%s", platformKey, suffix),
		Confidence:  0.7,
		Explanation: fmt.Sprintf("catalog platform %s is %s", platformKey, family),
	}

	if !strings.HasPrefix(suffix, "L") {
		return result, true
	}
	result.Model = suffix

	seriesForPlatform, ok := rockwellSeries[platformKey]
	if !ok {
		result.Explanation = fmt.Sprintf(
			"catalog platform %s is %s, and suffix %s marks a controller module",
			platformKey, family, suffix)
		return result, true
	}
	for prefix, series := range seriesForPlatform {
		if !strings.HasPrefix(suffix, prefix) {
			continue
		}
		result.Series = series
		result.Confidence = 0.9
		result.Explanation = fmt.Sprintf(
			"catalog platform %s is %s, and controller suffix %s identifies a %s",
			platformKey, family, suffix, series)
		return result, true
	}
	return result, true
}
