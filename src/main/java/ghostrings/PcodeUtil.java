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
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghostrings.exceptions.UnhandledOpArgsException;
import ghostrings.exceptions.UnhandledOpTypeException;

public class PcodeUtil {

    private static final Set<String> SP_REG_NAMES;
    static {
        SP_REG_NAMES = new HashSet<>();
        // Always use upper case
        SP_REG_NAMES.add("SP");
        SP_REG_NAMES.add("ESP");
        SP_REG_NAMES.add("RSP");
    }

    private final static long MAX_RECURSION_DEPTH = 10;

    private PcodeUtil() {
        // No instantiation
    }

    /**
     * Convenience function to create address object from address integer value.
     * Uses the integer as an offset in the program's default address space.
     * @param program Program to create an address for
     * @param offset Address as integer
     * @return Address object
     * @throws AddressOutOfBoundsException
     */
    public static Address addrFromLong(Program program, long offset) throws AddressOutOfBoundsException {
        // Use the value as an address in the program's default address space
        AddressSpace defaultAddrSpace = program.getAddressFactory().getDefaultAddressSpace();
        return defaultAddrSpace.getAddress(offset);
    }

    /**
     * Convenience function to create address object from address integer value.
     * Uses the integer as an offset in the program's default address space.
     * Returns null instead of throwing address-related exceptions.
     * @param program Program to create an address for
     * @param offset Address as integer
     * @return Address object or null
     */
    public static Address addrOrNullFromLong(Program program, long offset) {
        Address addr;
        try {
            addr = addrFromLong(program, offset);
        } catch (AddressOutOfBoundsException e) {
            return null;
        }
        return addr;
    }

    /**
     * Create a memory address from a constant value varnode.
     * 
     * @param program Program to create an address for
     * @param varnode Constant value varnode containing an address offset
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

        return addrFromLong(program, constVal);
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
    public static Long intAddStackOffset(FlatProgramAPI flatProgramAPI, PcodeOp op) {
        if (op.getOpcode() != PcodeOp.INT_ADD) {
            throw new IllegalArgumentException("Wrong op type");
        }

        // input 0: should be an SP register
        Varnode regVarnode = op.getInput(0);
        if (!isStackRegister(flatProgramAPI.getCurrentProgram(), regVarnode)) {
            return null;
        }

        // input 1: constant is the offset from SP
        Varnode offsetVarnode = op.getInput(1);
        List<Long> constants = PcodeUtil.getConstantInputs(flatProgramAPI, offsetVarnode);
        if (constants.isEmpty()) {
            return null;
        } else if (constants.size() == 1) {
            return constants.get(0);
        } else {
            // TODO: handle multiple constants
            return null;
        }
    }

    /**
     * Check if output varnode is based on a stack register offset. Returns SP
     * offset or null.
     * 
     * @throws UnhandledOpTypeException Op with stack register input has no handler
     * @throws UnhandledOpArgsException Unhandled inputs for op with stack input
     */
    public static Long outputStackOffset(FlatProgramAPI flatProgramAPI, Varnode storeLoc)
            throws UnhandledOpTypeException, UnhandledOpArgsException {
        PcodeOp defineOp = storeLoc.getDef();
        if (defineOp == null)
            return null;

        // So far, it's always been INT_ADD
        switch (defineOp.getOpcode()) {
        case PcodeOp.INT_ADD:
            return intAddStackOffset(flatProgramAPI, defineOp);
        }

        // TODO: Could have a MULTIEQUAL here with an input that's
        // a stack register defined by an INT_ADD (sp, offset)

        // The only use for this is to detect unhandled cases
        if (hasStackInput(flatProgramAPI.getCurrentProgram(), defineOp)) {
            throw new UnhandledOpTypeException("Unhandled op has stack register input: " + defineOp);
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
     * Attempt to resolve a varnode to constant values. Intended for use with the
     * "register" simplification style, which lacks some analysis steps.
     * 
     * If it's a constant, just returns the constant. If it's a register, check for
     * constants assigned to the register (can be multiple for multiequal).
     * 
     * @param program
     * @param varnode
     * @return List of input constants (may be empty)
     */
    public static List<Long> getConstantInputs(FlatProgramAPI programAPI, Varnode varnode) {
        return PcodeUtil.getConstantInputs(programAPI, varnode, 0);
    }

    private static List<Long> getConstantInputs(FlatProgramAPI programAPI, Varnode varnode, long depth) {
        List<Long> results = new LinkedList<>();

        // TODO check for cycles instead of simple max depth check?
        if (depth == MAX_RECURSION_DEPTH) {
            return results;
        }

        if (varnode.isConstant()) {
            results.add(varnode.getOffset());
        } else if (varnode.isRegister() && varnode.getDef() != null) {
            // Register may hold a constant
            PcodeOp def = varnode.getDef();

            switch (def.getOpcode()) {
            case PcodeOp.LOAD:
                // Check for LOAD op that loaded a constant into the register,
                // e.g. getting address from constant pool in ARM 32
                Program program = programAPI.getCurrentProgram();
                Address loadFrom = getLoadStoreAddr(def, program.getAddressFactory());
                Data dataLoaded = programAPI.getDataAt(loadFrom);
                if (dataLoaded != null) {
                    if (dataLoaded.isConstant()) {
                        Long constantValue = (Long) dataLoaded.getValue();
                        if (constantValue != null) {
                            results.add(constantValue);
                        }
                    } else if (dataLoaded.isPointer()) {
                        // If the data is a pointer, return its address as a constant
                        Address addrVal = (Address) dataLoaded.getValue();
                        if (addrVal != null) {
                            results.add(addrVal.getOffset());
                        }
                    }
                }
                break;

            case PcodeOp.COPY:
                // Noted for multiequal possible register values
                Varnode copyInput = def.getInput(0);
                results.addAll(getConstantInputs(programAPI, copyInput, depth + 1));
                break;

            case PcodeOp.MULTIEQUAL:
                // Recursively resolve multiequals input constants
                for (Varnode multiInput : def.getInputs()) {
                    results.addAll(getConstantInputs(programAPI, multiInput, depth + 1));
                }
                break;
            }
        }

        return results;
    }

}
