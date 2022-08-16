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

import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.ascii.AsciiCharSetRecognizer;
import ghostrings.exceptions.DuplicateDataException;
import ghostrings.exceptions.UnhandledOpArgsException;
import ghostrings.exceptions.UnhandledOpTypeException;

public class GhostringsUtil {

    private static final Set<String> SP_REG_NAMES;
    static {
        SP_REG_NAMES = new HashSet<>();
        // Always use upper case
        SP_REG_NAMES.add("SP");
        SP_REG_NAMES.add("ESP");
        SP_REG_NAMES.add("RSP");
    }

    private GhostringsUtil() {
        // No instantiation
    }

    public static String goStringSymbol(Program program) {
        if ("Mac OS X Mach-O".equals(program.getExecutableFormat())) {
            // Mach-O uses `_go.string.*`
            return "_go.string.*";
        }

        // ELF/PE use `go.string.*`
        return "go.string.*";
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

    /**
     * Create a memory address from a constant value varnode
     * 
     * @param program Program to create an address for
     * @param varnode Constant value varnode
     * @return Address in the program's default address space, with the constant
     *         value as its offset
     * @throws AddressOutOfBoundsException
     */
    public static Address addrFromConstant(Program program, Varnode varnode) throws AddressOutOfBoundsException {
        if (!varnode.isConstant()) {
            throw new IllegalArgumentException();
        }

        // The constant value is stored as its "address" offset
        long constVal = varnode.getAddress().getOffset();

        // Use the value as an address in the program's default address space
        AddressSpace defaultAddrSpace = program.getAddressFactory().getDefaultAddressSpace();
        return defaultAddrSpace.getAddress(constVal);
    }

    /** Check if register is a stack register */
    public static boolean isStackRegister(Register reg) {
        // "getTypeFlags() & Register.TYPE_SP" seems right but doesn't work for RSP
        final String regName = reg.getName();
        if (regName == null) {
            return false;
        }

        return SP_REG_NAMES.contains(regName.toUpperCase());
    }

    /** Check if varnode refers to a stack register */
    public static boolean isStackRegister(Program program, Varnode varnode) {
        Register reg = program.getRegister(varnode);
        if (reg != null && isStackRegister(reg)) {
            return true;
        }
        return false;
    }

    /** Check if Pcode op has the stack register as an input */
    public static boolean hasStackInput(Program program, PcodeOp op) {
        for (Varnode varnode : op.getInputs()) {
            if (isStackRegister(program, varnode)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get stack offset from INT_ADD op, or null if a stack offset can't be determined.
     * @param program
     * @param op
     * @return Stack offset long or null
     * @throws UnhandledOpArgsException
     */
    public static Long intAddStackOffset(Program program, PcodeOp op) throws UnhandledOpArgsException {
        if (op.getOpcode() != PcodeOp.INT_ADD) {
            throw new IllegalArgumentException("Wrong op type");
        }

        // input 0: should be an SP register
        Varnode regVarnode = op.getInput(0);
        if (!isStackRegister(program, regVarnode)) {
            return null;
        }

        // input 1: constant is the offset from SP
        Varnode offsetVarnode = op.getInput(1);
        if (!offsetVarnode.isConstant()) {
            // TODO: Input could be a register, which might have a defining op with a constant
            throw new UnhandledOpArgsException("Unhandled INT_ADD args");
        }

        return offsetVarnode.getOffset();
    }

    /**
     * Check if output varnode is based on a stack register offset. Returns SP
     * offset or null.
     * 
     * @throws UnhandledOpTypeException Op with stack register input has no handler
     * @throws UnhandledOpArgsException Unhandled inputs for op with stack input
     */
    public static Long outputStackOffset(Program program, Varnode storeLoc)
            throws UnhandledOpTypeException, UnhandledOpArgsException {
        PcodeOp defineOp = storeLoc.getDef();
        if (defineOp == null)
            return null;

        // So far, it's always been INT_ADD
        switch (defineOp.getOpcode()) {
        case PcodeOp.INT_ADD:
            return intAddStackOffset(program, defineOp);
        }

        // The only use for this is to detect unhandled cases
        if (hasStackInput(program, defineOp)) {
            throw new UnhandledOpTypeException("Unhandled op type");
        }

        return null;
    }

    /** Get the source/dest address from a LOAD/STORE op */
    public static Address getLoadStoreAddr(PcodeOp op, AddressFactory addrFactory) {
        if (op.getOpcode() != PcodeOp.STORE && op.getOpcode() != PcodeOp.LOAD)
            throw new IllegalArgumentException("Must be STORE or LOAD op");

        int spaceId = (int) op.getInput(0).getOffset();
        long offset = op.getInput(1).getOffset();

        // TODO: "If the wordsize attribute of the space given by the ID is bigger than
        // one, the offset into the space obtained from input1 must be multiplied by
        // this value in order to obtain the correct byte offset into the space."

        Address loadAddr = addrFactory.getAddress(spaceId, offset);
        return loadAddr;
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
