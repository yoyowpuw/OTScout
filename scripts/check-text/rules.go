package main

// The characters in this table are written as numeric escapes so that this file
// stays ASCII and is checked by the same rule it defines. Writing them literally
// would make the checker fail on its own source.

// replacement is what a writer should have typed instead.
type replacement struct {
	name string
	use  string
}

// namedRunes covers the characters that turn up by accident: pasted from a word
// processor, produced by an editor that helpfully converts quotes, or emitted by
// a language model. The message names the character because "non-ASCII at column
// 34" sends people hunting for something they cannot see.
var namedRunes = map[rune]replacement{
	'\u2010': {"hyphen", "-"},
	'\u2011': {"non-breaking hyphen", "-"},
	'\u2012': {"figure dash", "-"},
	'\u2013': {"en dash", "-"},
	'\u2014': {"em dash", "- or a comma"},
	'\u2015': {"horizontal bar", "-"},
	'\u2212': {"minus sign", "-"},
	'\u00ad': {"soft hyphen", "nothing, delete it"},

	'\u2018': {"left single quote", "'"},
	'\u2019': {"right single quote", "'"},
	'\u201a': {"low single quote", "'"},
	'\u201b': {"reversed single quote", "'"},
	'\u201c': {"left double quote", "\""},
	'\u201d': {"right double quote", "\""},
	'\u201e': {"low double quote", "\""},
	'\u00ab': {"left angle quote", "\""},
	'\u00bb': {"right angle quote", "\""},
	'\u2032': {"prime", "'"},
	'\u2033': {"double prime", "\""},

	'\u2026': {"ellipsis", "three dots"},
	'\u2022': {"bullet", "-"},
	'\u00b7': {"middle dot", "-"},
	'\u2027': {"hyphenation point", "-"},

	'\u00a0': {"non-breaking space", "a space"},
	'\u2007': {"figure space", "a space"},
	'\u2009': {"thin space", "a space"},
	'\u202f': {"narrow non-breaking space", "a space"},
	'\u200b': {"zero width space", "nothing, delete it"},
	'\u200c': {"zero width non-joiner", "nothing, delete it"},
	'\u200d': {"zero width joiner", "nothing, delete it"},
	'\u200e': {"left-to-right mark", "nothing, delete it"},
	'\u200f': {"right-to-left mark", "nothing, delete it"},
	'\ufeff': {"byte order mark", "nothing, delete it"},

	'\u00d7': {"multiplication sign", "x"},
	'\u00f7': {"division sign", "/"},
	'\u2122': {"trademark sign", "nothing, delete it"},
	'\u00a9': {"copyright sign", "the word Copyright"},
	'\u00ae': {"registered sign", "nothing, delete it"},
	'\u2264': {"less than or equal sign", "<="},
	'\u2265': {"greater than or equal sign", ">="},
	'\u2260': {"not equal sign", "!="},
}

// runeBlock is a range of code points described by one message, for the cases
// where listing every member would be pages of table and no clearer.
type runeBlock struct {
	lo, hi rune
	repl   replacement
}

var namedBlocks = []runeBlock{
	{'\u2190', '\u21ff', replacement{"an arrow", "-> or <-"}},
	{'\u27f0', '\u27ff', replacement{"an arrow", "-> or <-"}},
	{'\u2900', '\u297f', replacement{"an arrow", "-> or <-"}},
	{'\u2b00', '\u2bff', replacement{"an arrow or a geometric shape", "plain words"}},
	{'\u2600', '\u27bf', replacement{"a symbol or emoji", "plain words"}},
	{'\ufe00', '\ufe0f', replacement{"a variation selector, usually left over from an emoji", "nothing, delete it"}},
	{'\U0001f000', '\U0001faff', replacement{"an emoji", "plain words"}},
	{'\U0001f900', '\U0001f9ff', replacement{"an emoji", "plain words"}},
}

// phrases are rejected wherever they appear. Each one is a habit of generated
// prose rather than a word this project would ever need: filler that opens a
// paragraph without saying anything, marketing register, or the residue of a
// chat reply pasted into a file.
//
// The list is deliberately short and specific. A checker that fires on ordinary
// technical writing gets switched off, and then it protects nothing. Terms of art
// this project actually uses, "threat landscape" or "comprehensive" among them,
// are not here.
var phrases = []string{
	// Residue of a chat reply.
	"as an ai",
	"as a language model",
	"i hope this helps",
	"hope that helps",
	"let me know if you",
	"feel free to reach out",
	"great question",
	"here is a breakdown",
	"here's a breakdown",
	"you're absolutely right",
	"youre absolutely right",

	// Openers that delay the sentence without adding to it.
	"it is worth noting",
	"it's worth noting",
	"it is important to note",
	"it's important to note",
	"it should be noted",
	"needless to say",
	"first and foremost",
	"last but not least",
	"that being said",
	"at the end of the day",
	"in conclusion",
	"to summarize",
	"in today's",
	"in todays",

	// Marketing register.
	"cutting-edge",
	"cutting edge",
	"state-of-the-art",
	"game-changer",
	"game changer",
	"game-changing",
	"look no further",
	"we've got you covered",
	"weve got you covered",
	"rest assured",
	"unlock the power",
	"harness the power",
	"elevate your",
	"supercharge",
	"revolutionize",
	"revolutionizing",
	"paradigm shift",
	"hassle-free",
	"effortlessly",
	"seamlessly integrate",
	"seamless integration",
	"robust and scalable",
	"ever-evolving",
	"ever evolving",

	// Reaching for weight the sentence has not earned.
	"delve into",
	"a testament to",
	"plays a crucial role",
	"plays a vital role",
	"plays a key role",
	"navigate the complexities",
	"in the realm of",
	"in the world of",
	"embark on",
	"meticulously",
	"treasure trove",
	"the landscape of",
}
