package normalize

import (
	"fmt"
	"regexp"
	"strings"
)

// siemensMLFB parses the Siemens order number, called the MLFB.
//
// An MLFB such as 6ES7 214-1AG40-0XB0 breaks down as a product group prefix
// (6ES7 for SIMATIC controllers and I/O), then a type group whose first digits
// identify the model. A CPU 1214C is 6ES7 214, and the S7-1500 CPU 1516 is
// 6ES7 516. That mapping is what turns a bare order code into a product name an
// advisory can be matched against.
//
// The tables below cover the controller and panel ranges that appear most often
// in advisories. Extending them is a good first contribution: add the prefix or
// type group, and add a case to the golden tests.
type siemensMLFB struct{}

func init() { registerCatalogParser(siemensMLFB{}) }

func (siemensMLFB) Name() string { return "siemens-mlfb" }

// mlfbPattern matches the order code shape: a digit, two or three letters, then
// at least four more alphanumeric characters.
var mlfbPattern = regexp.MustCompile(`^([0-9][A-Z]{2}[0-9]?)([0-9A-Z]{4,})$`)

// siemensGroups maps the MLFB product group prefix to a product line.
var siemensGroups = map[string]string{
	"6ES7": "SIMATIC S7",
	"6ES5": "SIMATIC S5",
	"6AG1": "SIMATIC IPC",
	"6AG4": "SIMATIC IPC",
	"6AV2": "SIMATIC HMI",
	"6AV6": "SIMATIC HMI",
	"6AV7": "SIMATIC Panel PC",
	"6GK1": "SCALANCE",
	"6GK5": "SCALANCE",
	"6GK6": "RUGGEDCOM",
	"6SL3": "SINAMICS",
	"6SE7": "SIMOVERT",
	"6SE6": "MICROMASTER",
	"6ED1": "LOGO!",
	"6DL8": "SIMATIC PCS neo",
	"6DL3": "SIMATIC PCS 7",
	"6MD8": "SICAM",
	"7KM8": "SENTRON PAC",
	"7KG9": "SICAM",
}

// s7TypeGroups maps the leading digits of the type group to a controller family
// and model. The key is the first three digits after the product group.
var s7TypeGroups = map[string]struct {
	family string
	model  string
}{
	// S7-1200
	"211": {"SIMATIC S7-1200", "CPU 1211C"},
	"212": {"SIMATIC S7-1200", "CPU 1212C"},
	"214": {"SIMATIC S7-1200", "CPU 1214C"},
	"215": {"SIMATIC S7-1200", "CPU 1215C"},
	"217": {"SIMATIC S7-1200", "CPU 1217C"},
	// S7-1500
	"510": {"SIMATIC S7-1500", "CPU 1510SP"},
	"511": {"SIMATIC S7-1500", "CPU 1511"},
	"512": {"SIMATIC S7-1500", "CPU 1512"},
	"513": {"SIMATIC S7-1500", "CPU 1513"},
	"514": {"SIMATIC S7-1500", "CPU 1514"},
	"515": {"SIMATIC S7-1500", "CPU 1515"},
	"516": {"SIMATIC S7-1500", "CPU 1516"},
	"517": {"SIMATIC S7-1500", "CPU 1517"},
	"518": {"SIMATIC S7-1500", "CPU 1518"},
	// S7-300
	"312": {"SIMATIC S7-300", "CPU 312"},
	"313": {"SIMATIC S7-300", "CPU 313"},
	"314": {"SIMATIC S7-300", "CPU 314"},
	"315": {"SIMATIC S7-300", "CPU 315"},
	"316": {"SIMATIC S7-300", "CPU 316"},
	"317": {"SIMATIC S7-300", "CPU 317"},
	"318": {"SIMATIC S7-300", "CPU 318"},
	// S7-400
	"412": {"SIMATIC S7-400", "CPU 412"},
	"413": {"SIMATIC S7-400", "CPU 413"},
	"414": {"SIMATIC S7-400", "CPU 414"},
	"416": {"SIMATIC S7-400", "CPU 416"},
	"417": {"SIMATIC S7-400", "CPU 417"},
	// S7-200 SMART
	"288": {"SIMATIC S7-200 SMART", ""},
	// ET 200 distributed I/O interface modules
	"151": {"SIMATIC ET 200", "IM 151"},
	"153": {"SIMATIC ET 200", "IM 153"},
	"155": {"SIMATIC ET 200", "IM 155"},
}

func (p siemensMLFB) Parse(raw string) (CatalogResult, bool) {
	key := CatalogKey(raw)
	if len(key) < 8 {
		return CatalogResult{}, false
	}

	matches := mlfbPattern.FindStringSubmatch(key)
	if matches == nil {
		return CatalogResult{}, false
	}
	group, rest := matches[1], matches[2]

	line, known := siemensGroups[group]
	if !known {
		return CatalogResult{}, false
	}

	result := CatalogResult{
		Parser:     p.Name(),
		VendorID:   "siemens",
		Series:     line,
		Normalized: formatMLFB(group, rest),
		Confidence: 0.6,
	}
	if group == "6GK6" {
		result.VendorID = "ruggedcom"
	}

	if group == "6ES7" && len(rest) >= 3 {
		if entry, ok := s7TypeGroups[rest[:3]]; ok {
			result.Family = entry.family
			result.Model = entry.model
			result.Confidence = 0.9
			result.Explanation = fmt.Sprintf(
				"MLFB product group %s is %s, and type group %s identifies %s",
				group, line, rest[:3], strings.TrimSpace(entry.family+" "+entry.model))
			return result, true
		}
	}

	result.Family = line
	result.Explanation = fmt.Sprintf(
		"MLFB product group %s is %s, but type group %s is not in the model table",
		group, line, firstN(rest, 3))
	return result, true
}

// formatMLFB restores the conventional grouping so the UI shows the code the way
// it is printed on the device.
func formatMLFB(group, rest string) string {
	if len(rest) < 11 {
		return group + rest
	}
	return fmt.Sprintf("%s %s-%s-%s", group, rest[0:3], rest[3:8], rest[8:])
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
