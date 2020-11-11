package objx86coff

import (
	"sort"

	mcclient "github.com/pangine/pangineDSM-utils/mcclient"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// PrefixMap records all the prefix instructions supported for x86 coff
var PrefixMap = map[string]int{
	"lock":  1,
	"repne": 1,
	"repnz": 1,
	"rep":   1,
	"repz":  1,
	"repe":  1,
}

// InstLstFixForPrefix will read the input instruction set and output a new set
// with prefix instructions spearated as single instructions.
func (objectcoff ObjectCoff) InstLstFixForPrefix(inque []int, bi pstruct.BinaryInfo) (outque []int) {
	sort.Ints(inque)
	outque = make([]int, 0)
	for len(inque) > 0 {
		vIP := inque[0]
		inque = inque[1:]
		if !pstruct.VAisValid(bi.ProgramHeaders, vIP) {
			continue
		}
		pIP := pstruct.V2PConv(bi.ProgramHeaders, vIP)
		res := mcclient.SendResolve(pIP, bi.Sections.Data)
		if !res.IsInst() || res.TakeBytes() == 0 {
			continue
		}
		outque = append(outque, vIP)
		inst, err := res.Inst()
		if err != nil {
			continue
		}
		instLen := int(res.TakeBytes())
		insnType := objectcoff.TypeInst(inst, instLen)
		if len(insnType.Prefixes) == 0 {
			continue
		}
		for len(inque) > 0 {
			nextOffset := inque[0]
			for !pstruct.VAisValid(bi.ProgramHeaders, nextOffset) && len(inque) > 0 {
				inque = inque[1:]
				nextOffset = inque[0]
			}
			nextPOffset := pstruct.V2PConv(bi.ProgramHeaders, nextOffset)
			if nextPOffset-pIP < instLen {
				// Two instructions cat to one
				inque = inque[1:]
			} else {
				break
			}
		}
	}
	return
}
