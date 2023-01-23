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

public class GoStaticStrings extends GhidraScript {

    private int ptrSize;
    private boolean bigEndian;
    private DataConverter dataConverter;

    private Address stringsStartAddr = null;
    private Address stringsEndAddr = null;

    static String hexAscii(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }

        return sb.toString();
    }

    /**
     * Use go.string boundary info if available to determine if potential string
     * address is located in go.string
     * 
     * @param addr Potential string address to check
     * @return True if the address doesn't violate known address boundaries
     */
    protected boolean addrInBounds(Address addr) {
        if (stringsStartAddr != null && addr.compareTo(stringsStartAddr) < 0) {
            return false;
        }

        if (stringsEndAddr != null && addr.compareTo(stringsEndAddr) >= 0) {
            return false;
        }

        return true;
    }

    protected boolean addrsInSameBlock(Address addr1, Address addr2) {
        MemoryBlock block1 = currentProgram.getMemory().getBlock(addr1);
        MemoryBlock block2 = currentProgram.getMemory().getBlock(addr2);

        return block1.equals(block2);
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
                    addr = GhostringsUtil.addrFromLong(currentProgram, addrInt);
                } catch (AddressOutOfBoundsException e) {
                    continue;
                }

                // Use go.string boundary info if available
                if (!addrInBounds(addr)) {
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
                                printf("defined @ %s: %s\n", addr, StringUtilities.convertControlCharsToEscapeSequences(checkStr));
                            }
                        } catch (Exception e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
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

        // Use go.string.* - go.func.* as boundaries if possible
        List<Symbol> startSyms = GhostringsUtil.findGoStringSymbol(this);
        List<Symbol> endSyms = GhostringsUtil.findGoFuncSymbol(this);

        if (startSyms.size() == 1 && endSyms.size() == 1) {
            Address goStringAddr = startSyms.get(0).getAddress();
            Address goFuncAddr = endSyms.get(0).getAddress();

            // Should normally be in same block
            if (addrsInSameBlock(goStringAddr, goFuncAddr) && goStringAddr.compareTo(goFuncAddr) < 0) {
                stringsStartAddr = goStringAddr;
                printf("using %s @ %s as the start boundary\n",
                        startSyms.get(0).getName(),
                        stringsStartAddr);

                stringsEndAddr = goFuncAddr;
                printf("using %s @ %s as the end boundary\n",
                        endSyms.get(0).getName(),
                        stringsEndAddr);
            }
        }

        MemoryBlock roBlock;
        if (stringsStartAddr != null) {
            // assume go.string.* and static allocated structs are in the same block
            roBlock = currentProgram.getMemory().getBlock(stringsStartAddr);
        } else {
            // TODO: Golang util API should provide the name of the rodata block for this
            // program
            roBlock = currentProgram.getMemory().getBlock(".rodata");
        }

        checkBlock(roBlock);
    }

}
