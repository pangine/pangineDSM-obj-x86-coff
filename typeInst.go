package objx86coff

import (
	"fmt"
	"strconv"
	"strings"

	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

var condMap = map[string]bool{
	"ja":     true,
	"jae":    true,
	"jb":     true,
	"jbe":    true,
	"jc":     true,
	"jcxz":   true,
	"jecxz":  true,
	"jrcxz":  true,
	"je":     true,
	"jg":     true,
	"jge":    true,
	"jl":     true,
	"jle":    true,
	"jna":    true,
	"jnae":   true,
	"jnb":    true,
	"jnbe":   true,
	"jnc":    true,
	"jne":    true,
	"jng":    true,
	"jnge":   true,
	"jnl":    true,
	"jnle":   true,
	"jno":    true,
	"jnp":    true,
	"jns":    true,
	"jnz":    true,
	"jo":     true,
	"jp":     true,
	"jpe":    true,
	"jpo":    true,
	"js":     true,
	"jz":     true,
	"loop":   true,
	"loope":  true,
	"loopne": true,
	"loopnz": true,
	"loopz":  true,
}

var jmpMap = map[string]pstruct.JmpBits{
	"jmp":  pstruct.Default,
	"jmpq": pstruct.Bits64,
	"jmpl": pstruct.Bits32,
}

var callMap = map[string]pstruct.JmpBits{
	"call":  pstruct.Default,
	"callq": pstruct.Bits64,
	"calll": pstruct.Bits32,
}

var retMap = map[string]bool{
	"\tret":       true,
	"\tretq":      true,
	"\tretl":      true,
	"\trep\tretq": true,
	"\trep\tretl": true,
}

var haltMap = map[string]bool{
	"\thlt": true,
}

var nopMap = map[string]bool{
	"nop":  true,
	"nopl": true,
	"nopw": true,
}
var specialNopMap = map[string]bool{
	"\tmovl\t%esi, %esi":        true, // 2 bytes
	"\tmovl\t%edi, %edi":        true,
	"\tleal\t(%esi), %esi":      true, // 3 bytes or 6 bytes
	"\tleal\t(%edi), %edi":      true,
	"\tleal\t(%esi,%eiz), %esi": true, // 4 bytes or 7 bytes
	"\tleal\t(%edi,%eiz), %edi": true,
}

// TypeInst convert string instruction into InstFlags
func (objectcoff ObjectCoff) TypeInst(s string, n int) (flg pstruct.InstFlags) {
	flg.InstSize = n
	flg.OriginInst = s
	fields := strings.Fields(s)
	var afterPrefix int
	for ; afterPrefix < len(fields); afterPrefix++ {
		if _, ok := PrefixMap[fields[afterPrefix]]; ok {
			flg.Prefixes = append(flg.Prefixes, fields[afterPrefix])
		} else {
			break
		}
	}
	if afterPrefix == len(fields) {
		fmt.Printf("WARNING: Insn %s only contains prefixes\n", s)
		return
	}
	if _, ok := condMap[fields[afterPrefix]]; ok {
		flg.IsConditional = true
		offset, err := strconv.ParseInt(fields[afterPrefix+1], 10, 32)
		if err != nil {
			panic(err)
		}
		flg.JmpOffset = int(offset)
	}
	if bits, ok := jmpMap[fields[afterPrefix]]; ok {
		flg.IsJmp = true
		flg.JmpBits = bits
		offset, err := strconv.ParseInt(fields[afterPrefix+1], 10, 32)
		if err != nil {
			flg.IsIndJmp = true
			flg.IndJmpTarget = fields[afterPrefix+1]
		} else {
			flg.JmpOffset = int(offset)
		}
	}
	if bits, ok := callMap[fields[afterPrefix]]; ok {
		flg.IsCall = true
		flg.JmpBits = bits
		offset, err := strconv.ParseInt(fields[afterPrefix+1], 10, 32)
		if err != nil {
			flg.IsIndJmp = true
			flg.IndJmpTarget = fields[afterPrefix+1]
		} else {
			flg.JmpOffset = int(offset)
		}
	}
	if _, ok := retMap[s]; ok {
		flg.IsRet = true
		flg.FlowStop = true
	}
	if _, ok := haltMap[s]; ok {
		flg.IsHlt = true
		flg.FlowStop = true
	}

	_, ok1 := nopMap[fields[afterPrefix]]
	_, ok2 := specialNopMap[s]
	if ok1 || ok2 {
		flg.IsNop = true
	}
	return
}
