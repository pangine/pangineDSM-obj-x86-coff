package objx86coff

import (
	"debug/pe"
	"fmt"

	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// ParseObj use go built in container parser to parse an elf object
func (objectcoff ObjectCoff) ParseObj(file string) (bi pstruct.BinaryInfo) {
	b, err := pe.Open(file)
	if err != nil {
		panic("file open error")
	}
	defer b.Close()

	// Read the image base for load
	var imageBase int
	switch oh := b.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = int(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = int(oh.ImageBase)
	}

	s := b.Sections
	nsct := len(s)
	if nsct == 0 {
		fmt.Printf("file %v is empty", file)
	} else {
		maxbyteslen := 0
		for _, is := range s {
			byteslen := int(is.Offset)
			b, err := is.Data()
			if err != nil {
				continue
			} else {
				byteslen += len(b)
			}
			if byteslen > maxbyteslen {
				maxbyteslen = byteslen
			}
		}
		bi.Sections.Data = make([]uint8, maxbyteslen)
		bi.ProgramHeaders = make([]pstruct.ProgramHeader, 0)
		offset := 0
		maxReach := 0
		for _, is := range s {
			if imageBase != 0 || is.VirtualAddress != 0 {
				// obj files does not have virtual addresses
				bi.ProgramHeaders = append(bi.ProgramHeaders,
					pstruct.ProgramHeader{
						PAddr: int(is.Offset),
						VAddr: imageBase + int(is.VirtualAddress),
					})
			}
			bi.Sections.Name = append(bi.Sections.Name, is.Name)
			bi.Sections.Offset = append(bi.Sections.Offset, int(is.Offset))
			noffset := int(is.Offset)
			if maxReach > offset {
				offset = maxReach
			}
			for j := offset; j < noffset; j++ {
				// Fill differences with NOP (0x90)
				bi.Sections.Data[j] = 0x90
			}
			offset = noffset
			data, err := is.Data()
			if err != nil {
				noffset = offset
			} else {
				noffset = offset + len(data)
			}

			if noffset > maxReach {
				maxReach = noffset
			}
			for j := offset; j < noffset; j++ {
				bi.Sections.Data[j] = data[j-offset]
			}
			offset = noffset
		}
	}
	return
}
