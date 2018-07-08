package messages

// Message Messages, Warnings, Errors used by Celo.
type Message uint16

// Messages keys
const (
	PhraseRead            Message = iota //
	PhraseConfirm                        //
	PhraseWarningMismatch                //
)

// Messages is a map with string values for a given Message key.
var Messages = map[Message]string{
	PhraseRead:            "Enter Phrase:",
	PhraseConfirm:         "Confirm Phrase:",
	PhraseWarningMismatch: "Phrases don't match, please try again",
}

// String returns the message string.
func (m Message) String() string {
	return Messages[m]
}
