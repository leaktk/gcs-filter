package scanner

type leakData struct {
	AddedDate       string   `json:"AddedDate"`
	DataClasses     []string `json:"DataClasses"`
	FilePath        string   `json:"FilePath"`
	LeakURL         string   `json:"LeakURL"`
	Line            string   `json:"Line"`
	LineNumber      int      `json:"LineNumber"`
	Offender        string   `json:"Offender"`
	OffenderEntropy float64  `json:"OffenderEntropy"`
	Rule            string   `json:"Rule"`
}

// Leak contains the information from a leak formatted in a way that should be
// used for downstream reporters
type Leak struct {
	ID   string   `json:"id"`
	Type string   `json:"type"`
	Data leakData `json:"data"`
}

// IsProductionSecretRule checks the tags of a leak to see if they indicate the
// rule is production ready
func (l *Leak) IsProductionSecretRule() bool {
	isSecret := false
	isTesting := false

	for _, tag := range l.Data.DataClasses {
		if !isSecret && tag == "type:secret" {
			isSecret = true
		}

		if !isTesting && tag == "group:leaktk-testing" {
			isTesting = true
		}
	}

	return isSecret && !isTesting
}
