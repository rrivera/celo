package messages

// Messages, Warnings, Errors used by Celo.
type Message uint16

const (
	PhraseRead            Message = iota //
	PhraseConfirm                        //
	PhraseWarningMismatch                //
)

var Messages map[Message]string = map[Message]string{
	PhraseRead:            "Enter Phrase:",
	PhraseConfirm:         "Confirm Phrase:",
	PhraseWarningMismatch: "Phrases don't match, please try again",
}

func (m Message) String() string {
	return Messages[m]
}
