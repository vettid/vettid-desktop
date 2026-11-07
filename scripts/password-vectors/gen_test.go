// The generator of src-tauri/src/credential/passwords/estimator-vectors.json
// (#13 item 4a): it runs the vault's own password rule over 1,398 passwords.
//
// To run it: copy vettid-vault's vms/recovery/password.go and its two lists
// (at the commit named in password_rule.rs) into a folder `pw` with this file
// and a consts.go giving MaxPasswordBytes = 1024, MinPasswordRunes = 12 and
// GuessabilityFloor = 1e10 (from recovery.go); next to `pw`, a go.mod with
// golang.org/x/text at the vault's version and testdata/passwords/verdicts.json.
// Then, with the vault's Go toolchain (its Unicode tables decide `nd`):
//
//   GOTOOLCHAIN=local PWGEN_OUT=$PWD/estimator-vectors.json go test ./pw/ -run TestGen
//
// The random parts are seeded (13), so the same Go gives the same file.

package recovery

import (
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode"
)

type vec struct {
	Password string   `json:"password"`
	Guesses  *float64 `json:"guesses"`
	Vault    string   `json:"vault"`
	App      string   `json:"app"`
}

func verdictAt(pw string, floor float64) string {
	n, ok := NormalizePassword([]byte(pw))
	if !ok {
		return "invalid"
	}
	rs := []rune(string(n))
	switch {
	case len(rs) < MinPasswordRunes:
		return ReasonShort
	case oneRepeated(rs):
		return ReasonRepeated
	}
	if _, ok := common[lowerASCII(string(n))]; ok {
		return ReasonCommon
	}
	if Guesses(string(n)) < floor {
		return ReasonGuessable
	}
	return "ok"
}

func TestGen(t *testing.T) {
	out := os.Getenv("PWGEN_OUT")
	if out == "" {
		t.Skip()
	}
	bs := string(rune(92))
	tab := string(rune(9))
	comb := string(rune(0x301))
	ring := string(rune(0x30a))
	kelvin := string(rune(0x212a))
	nbsp := string(rune(0xa0))
	var pws []string
	add := func(s ...string) { pws = append(pws, s...) }
	b, _ := os.ReadFile("../testdata/passwords/verdicts.json")
	var f struct{ Cases []struct{ Password string } }
	json.Unmarshal(b, &f)
	for _, c := range f.Cases {
		add(c.Password)
	}
	for _, lst := range []map[string]int{common, words} {
		for w := range lst {
			rs := []rune(w)
			add(w, strings.ToUpper(w), strings.ToUpper(w[:1])+w[1:], reverse(w), w+"2026", "x"+w+"!", w+w)
			l := []rune(w)
			for i, r := range l {
				switch r {
				case 'a':
					l[i] = '@'
				case 'o':
					l[i] = '0'
				case 'e':
					l[i] = '3'
				case 's':
					l[i] = '$'
				}
			}
			add(string(l), string(l)+"Q9z", strings.ToUpper(string(rs[0]))+string(l[1:]))
			if len(rs) > 3 {
				mixed := []rune(w)
				mixed[1] = unicode.ToUpper(mixed[1])
				mixed[len(mixed)-1] = unicode.ToUpper(mixed[len(mixed)-1])
				add(string(mixed), string(mixed)+"-91-moss")
			}
		}
	}
	add("abcdefghijklmnop", "zyxwvutsrqponm", "acegikmoqsuw", "13579135791357", "9876543210987",
		"qwertyuiop", "poiuytrewq", "1qaz2wsx3edc4rfv", "asdfghjkl;'zxcv", "QWERTYuiopASDF", "`1234567890-=qq",
		"qwertyuiop[]"+bs+"asd", "12/31/1999xyzw", "1999-12-31-2000", "2024.01.01 abcd", "19991231abcdefgh", "aaaaaaaaaaaab", "abababababab",
		"abcabcabcabcabc", "Tr0ub4dor&3", "Tr0ub4dor&3xyz", "horse battery staple correct", "a b c d e f g h i j",
		"İSTANBULİSTANBUL", "İstanbul2024!x", "ΣΟΦΙΑσοφίαΣΟΦΙΑΣ", "σοφίασοφίαςxx", "Straße-Straße-12", "STRASSEstrasse",
		"ǅungla-ǅungla12", "ﬁnancial-ﬁle-ok", "١٢٣٤٥٦٧٨٩٠١٢", "١٩٩٩-١٢-٣١abcdef", "ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩⅪⅫ", "²³⁴⁵⁶⁷⁸⁹¹²³⁴",
		"０１２３４５６７８９０１", "ＡＢＣＤＥＦＧＨＩＪＫＬ", "密码密码密码密码密码a1", "密码密码密码密码密码密码", "パスワードパスワード12",
		"😀😀😀😀😀😀😀😀😀😀😀😀", "😀😁😂🤣😃😄😅😆😉😊😋😎", "café au lait!!", "cafe"+comb+" au lait!!", "A"+ring+"ngström-12-x",
		kelvin+"elvin-temp-12", "PASSWORD123"+kelvin, "pa"+nbsp+"ss"+nbsp+"word"+nbsp+"123", tab+"password1234", "password1234 ", "Password1234",
		"PASSWORD1234", "pAssword1234", "drowssap4321", "4321drowssap", "p@ssw0rd1234", "P@SSW0RD1234",
		"monkeydragon12", "dragonmonkeysunshine", "sunshine-princess", "football1999!!", "baseball2024baseball",
		"ΑΒΓΔΕΖΗΘΙΚΛΜ", "абвгдеёжзийк", "ⅰⅱⅲⅳⅴⅵⅶⅷⅸⅹⅺⅻ", "٠١٢٣٤٥٦٧٨٩٠١", "০১২৩৪৫৬৭৮৯০১", "1/2/3/4/5/6/7", "........1234")
	add(strings.Repeat("ab", 70), strings.Repeat("a", 129), strings.Repeat("xyz", 43), strings.Repeat("Zq9!", 32), strings.Repeat("é", 600),
		strings.Repeat("Zq9!", 31)+"abcd", strings.Repeat("x", 1024), strings.Repeat("x", 1025))
	r := rand.New(rand.NewSource(13))
	alpha := []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*()-_=+[]{};:'\",.<>/?|`~ " + bs, "éøßñü密码Ωж١"}
	for i := 0; i < 400; i++ {
		n := 1 + r.Intn(30)
		k := 1 + r.Intn(len(alpha))
		var sb strings.Builder
		for j := 0; j < n; j++ {
			set := []rune(alpha[r.Intn(k)])
			sb.WriteRune(set[r.Intn(len(set))])
		}
		add(sb.String())
	}
	wl := make([]string, 0, len(words))
	for w := range words {
		wl = append(wl, w)
	}
	for i := 0; i < 150; i++ {
		n := 1 + r.Intn(4)
		parts := []string{}
		for j := 0; j < n; j++ {
			w := wl[r.Intn(len(wl))]
			switch r.Intn(4) {
			case 1:
				w = strings.ToUpper(w[:1]) + w[1:]
			case 2:
				w = reverse(w)
			}
			parts = append(parts, w)
		}
		sep := []string{"", " ", "-", "1", "!"}[r.Intn(5)]
		add(strings.Join(parts, sep) + []string{"", "7", "2024", "!!"}[r.Intn(4)])
	}
	between := 0
	for i := 0; i < 200000 && between < 40; i++ {
		var sb strings.Builder
		n := 12 + r.Intn(6)
		for j := 0; j < n; j++ {
			set := []rune(alpha[r.Intn(3)])
			if r.Intn(3) == 0 {
				sb.WriteString(wl[r.Intn(len(wl))])
				j += 4
				continue
			}
			sb.WriteRune(set[r.Intn(len(set))])
		}
		s := sb.String()
		if g := Guesses(s); g >= 1e10 && g < 2e10 && verdictAt(s, 1e10) == "ok" {
			add(s)
			between++
		}
	}
	seen := map[string]bool{}
	var vs []vec
	for _, p := range pws {
		if seen[p] {
			continue
		}
		seen[p] = true
		v := vec{Password: p, Vault: verdictAt(p, 1e10), App: verdictAt(p, 2e10)}
		if n, ok := NormalizePassword([]byte(p)); ok {
			g := Guesses(string(n))
			if !math.IsInf(g, 1) {
				v.Guesses = &g
			}
		}
		vs = append(vs, v)
	}
	var nd [][2]int
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if unicode.IsDigit(c) {
			if len(nd) > 0 && nd[len(nd)-1][1] == int(c)-1 {
				nd[len(nd)-1][1] = int(c)
			} else {
				nd = append(nd, [2]int{int(c), int(c)})
			}
		}
	}
	j, _ := json.MarshalIndent(map[string]any{"unicode": unicode.Version, "nd": nd, "cases": vs}, "", " ")
	os.WriteFile(out, j, 0o644)
	t.Logf("%d cases, %d Nd ranges, unicode %s", len(vs), len(nd), unicode.Version)
}
