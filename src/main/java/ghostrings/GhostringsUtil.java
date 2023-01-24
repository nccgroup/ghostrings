/* ###
 * Ghostrings
 * Copyright (C) 2022  NCC Group
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
package ghostrings;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.ascii.AsciiCharSetRecognizer;
import ghostrings.exceptions.DuplicateDataException;

public class GhostringsUtil {

    private final static HashMap<String, String> STR_MEM_BLOCKS_MAP;
    static {
        STR_MEM_BLOCKS_MAP = new HashMap<>();
        STR_MEM_BLOCKS_MAP.put(ElfLoader.ELF_NAME, ".rodata");
        STR_MEM_BLOCKS_MAP.put(PeLoader.PE_NAME, ".rdata");
        STR_MEM_BLOCKS_MAP.put(MachoLoader.MACH_O_NAME, "__rodata");
    }

    private GhostringsUtil() {
        // No instantiation
    }

    public static List<String> goStringSymbols(Program program) {
        if (MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
            // Mach-O uses `_go.string.*`
            return Arrays.asList("_go.string.*", "_go:string.*");
        }

        // ELF/PE use `go.string.*`
        return Arrays.asList("go.string.*", "go:string.*");
    }

    public static List<String> goFuncSymbols(Program program) {
        if (MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
            // Mach-O uses `_go.func.*`
            return Arrays.asList("_go.func.*", "_go:func.*");
        }

        // ELF/PE use `go.func.*`
        return Arrays.asList("go.func.*", "go:func.*");
    }

    private static List<Symbol> findAllSymbols(FlatProgramAPI flatProgramAPI, List<String> symbolNames) {
        List<Symbol> results = new LinkedList<>();

        for (String curSymbolName : symbolNames) {
            List<Symbol> foundSymbols = flatProgramAPI.getSymbols(curSymbolName, null);
            results.addAll(foundSymbols);
        }

        return results;
    }

    public static List<Symbol> findGoStringSymbol(FlatProgramAPI flatProgramAPI) {
        Program program = flatProgramAPI.getCurrentProgram();
        List<String> symbolNames = goStringSymbols(program);
        return findAllSymbols(flatProgramAPI, symbolNames);
    }

    public static List<Symbol> findGoFuncSymbol(FlatProgramAPI flatProgramAPI) {
        Program program = flatProgramAPI.getCurrentProgram();
        List<String> symbolNames = goFuncSymbols(program);
        return findAllSymbols(flatProgramAPI, symbolNames);
    }

    public static String getFuncName(Function func) {
        if (func.getName() != null)
            return func.getName();
        return "(undefined)";
    }

    public static String funcNameAndAddr(Function func) {
        return String.format(
                "%s @ %s",
                getFuncName(func),
                func.getEntryPoint().toString());
    }

    public static String memBlockName(Program program, Address addr) {
        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) {
            return null;
        }
        return block.getName();
    }

    public static String roDataBlockName(Program program) {
        String progFormat = program.getExecutableFormat();
        if (progFormat == null) {
            return null;
        }

        return STR_MEM_BLOCKS_MAP.get(progFormat);
    }

    /**
     * Check if address is in a memory block where string data is stored (e.g., rodata).
     * @param program Program reference
     * @param addr Address to check
     * @return True if address is in rodata, false if not.
     */
    public static boolean isAddrInStringMemBlock(Program program, Address addr) {
        String blockName = GhostringsUtil.memBlockName(program, addr);
        if (blockName == null) {
            return false;
        }

        String progRoBlockName = roDataBlockName(program);
        if (progRoBlockName == null) {
            return false;
        }

        return progRoBlockName.equals(blockName);
    }

    /**
     * Check if a region of memory contains only ASCII characters.
     * 
     * @param program    Program
     * @param stringAddr Address to begin checking for ASCII characters
     * @param stringLen  Length of the string to check
     * @return String data if all bytes at the address are ASCII characters, or null
     *         if there are rejected characters
     */
    public static String checkForString(Program program, Address stringAddr, int stringLen) {
        if (stringLen <= 0) {
            throw new IllegalArgumentException("String length must be greater than 0");
        }

        if (!stringAddr.isLoadedMemoryAddress()) {
            return null;
        }

        AsciiCharSetRecognizer asciiRec = new AsciiCharSetRecognizer();

        StringBuilder sb = new StringBuilder();
        try {
            for (long i = 0; i < stringLen; i++) {
                Byte curByte = program.getMemory().getByte(stringAddr);

                // TODO Detect non-ASCII strings
                // See ghidra.util.ascii and StringUtilities for useful methods
                if (!asciiRec.contains(curByte))
                    return null;

                sb.append((char) (curByte & 0xff));

                stringAddr = stringAddr.addNoWrap(1);
            }
        } catch (MemoryAccessException | AddressOverflowException e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
            return null;
        }

        return sb.toString();
    }

    /**
     * Try to define a string, with some checks for conflicting data.
     * @param script Script instance for the program being analyzed
     * @param stringAddr Address to create the string at
     * @param checkString Expected string data to be defined
     * @param verbose Log messages about conflicting data
     * @return True if the string data is defined, false if not.
     * @throws Exception
     */
    public static boolean tryDefString(GhidraScript script, Address stringAddr, String checkString, int verbose) throws Exception {
        // Check for conflicting data definition
        final Data conflictData = script.getDataContaining(stringAddr);
        if (conflictData != null) {
            if (verbose > 0)
                script.println("Conflicting data: " + conflictData.toString());

            if (!conflictData.hasStringValue()) {
                // If it's an "undefined" type entry just delete it
                DataType dType = conflictData.getDataType();
                if (Undefined.isUndefined(dType)) {
                    if (verbose > 0)
                        script.println("Removing undefined data type");

                    script.removeData(conflictData);
                } else {
                    if (verbose > 0)
                        script.println("Unhandled non-string conflicting data, skipping");
                    return false;
                }
            } else {
                // Handle conflicting string data
                final String conflictString = (String) conflictData.getValue();
                final boolean sameStartAddr = stringAddr.equals(conflictData.getAddress());

                if (sameStartAddr && checkString.equals(conflictString)) {
                    // TODO might be cleaner as a separate "check string already exists" method
                    throw new DuplicateDataException("Found already defined string");
                } else if (sameStartAddr && checkString.length() > conflictString.length()) {
                    // Existing string is smaller
                    if (verbose > 0)
                        script.println("Taking larger new value");

                    script.removeDataAt(stringAddr);
                } else {
                    // Existing data is larger or has a different start address:
                    // might be bad glob, or other false positive
                    return false;
                }
            }
        }

        script.createAsciiString(stringAddr, checkString.length());
        return true;
    }

}
