/* ###
 * Ghostrings
 * Copyright (C) 2023  NCC Group
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
//Find Go strings statically allocated in read-only memory.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.StringUtilities;
import ghostrings.GhostringsUtil;
import ghostrings.GolangProgramInfo;
import ghostrings.PcodeUtil;
import ghostrings.exceptions.DuplicateDataException;

public class GoStaticStrings extends GhidraScript {

    private int ptrSize;
    private boolean bigEndian;
    private DataConverter dataConverter;
    private GolangProgramInfo golangInfo;

    static String hexAscii(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }

        return sb.toString();
    }

    protected void checkBlock(MemoryBlock roBlock) throws MemoryAccessException {
        Address blockStart = roBlock.getStart();
        Address blockEnd = roBlock.getEnd();
        Address blockStructEnd = blockEnd.subtract(ptrSize);

        if (blockStructEnd.compareTo(blockStart) <= 0) {
            printf("not enough space in this block\n");
            return;
        }

        for (Address curAddr = blockStart; curAddr.compareTo(blockStructEnd) < 0; curAddr = curAddr.add(ptrSize)) {
            if (monitor.isCancelled())
                break;

            byte[] addrBytes = new byte[ptrSize];
            if (roBlock.getBytes(curAddr, addrBytes) == ptrSize) {
                // check if it looks like an address,
                // check for length value after possible address,
                // then check for string data
                long addrInt = dataConverter.getValue(addrBytes, addrBytes.length);

                //printf("%s = 0x%x\n", hexAscii(addrBytes), addrInt);

                Address addr;
                try {
                    addr = PcodeUtil.addrFromLong(currentProgram, addrInt);
                } catch (AddressOutOfBoundsException e) {
                    continue;
                }

                // Use go.string boundary info if available
                if (!golangInfo.isAddrInStringData(addr)) {
                    continue;
                }

                byte[] lenBytes = new byte[ptrSize];
                if (roBlock.getBytes(curAddr.add(ptrSize), lenBytes) == ptrSize) {
                    Long lenInt = dataConverter.getValue(lenBytes, lenBytes.length);
                    int length = lenInt.intValue();

                    if (length <= 0) {
                        continue;
                    }

                    String checkStr = GhostringsUtil.checkForString(currentProgram, addr, length);
                    if (checkStr != null) {
                        try {
                            if (GhostringsUtil.tryDefString(this, addr, checkStr, 0)) {
                                printf("Defined @ %s: %s\n", addr, StringUtilities.convertControlCharsToEscapeSequences(checkStr));
                            }
                        } catch (DuplicateDataException e) {
                            // This exact string is already defined
                            printf("Already defined @ %s: %s\n", addr, StringUtilities.convertControlCharsToEscapeSequences(checkStr));
                        } catch (Exception e) {
                            printf("Define failed with exception: %s\n", e.getMessage());
                        }
                    }
                }
            }
        }
    }

    @Override
    protected void run() throws Exception {
        ptrSize = currentProgram.getDefaultPointerSize();
        printf("pointer size: %d\n", ptrSize);

        bigEndian = currentProgram.getLanguage().isBigEndian();
        if (bigEndian) {
            printf("Big endian\n");
            dataConverter = BigEndianDataConverter.INSTANCE;
        } else {
            printf("Little endian\n");
            dataConverter = LittleEndianDataConverter.INSTANCE;
        }

        golangInfo = new GolangProgramInfo(this, true);

        MemoryBlock roBlock = golangInfo.getRoDataBlock();
        if (roBlock == null) {
            printf("Couldn't determine rodata block\n");
            return;
        }

        checkBlock(roBlock);
    }

}
