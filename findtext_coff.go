package objx86coff

import (
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// FindObjectText returns the index of text section from the input for elf file
func (objectcoff ObjectCoff) FindObjectText(sec pstruct.Sections) (lo, hi int) {
	s := len(sec.Name)
	var i int
	for i = 0; i < s; i++ {
		if sec.Name[i] == ".text" {
			lo = sec.Offset[i]
			break
		}
	}
	if i >= s {
		panic("There is no text section")
	}
	if i == s-1 {
		hi = len(sec.Data)
	} else {
		hi = sec.Offset[i+1]
	}
	return
}
