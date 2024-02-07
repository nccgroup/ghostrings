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
//Find Go strings dynamically allocated on the stack (P-Code based).
//Clearing out all automatically defined strings in .rodata/.rdata/__rodata first is recommended.
//The built-in ASCII Strings analysis can then be run again afterwards,
//with the option to clear existing strings disabled.
//
//This version uses a hack combined with the "normalize" simplification
//style to preserve nicer COPY operations in the PCode output,
//which clearly indicate a constant value being copied to the stack.
//
//NOTE: The hack this script depends on breaks in Ghidra 10.2.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding 
//@menupath 
//@toolbar 

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import docking.options.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghostrings.AddressCandidate;
import ghostrings.GhostringsUtil;
import ghostrings.LengthCandidate;
import ghostrings.PcodeUtil;

public class GoDynamicStringsHigh extends GoDynamicStrings {

    private static final String SIMPLIFICATION_STYLE = "normalize";

    @Override
    protected String getSimplificationStyle() {
        return SIMPLIFICATION_STYLE;
    }

    @Override
    protected DecompileOptions makeDecompileOptions(GhidraState state) {
        DecompileOptions options = new DecompileOptions();

        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, state.getCurrentProgram());
            }
        }

        options.setEliminateUnreachable(false);

        // HACK to turn off deadcode rule
        // Really, it's abusing XML injection in setProtoEvalModel to
        // add XML config that's not exposed through the interface.
        String protoEvalModel = options.getProtoEvalModel();
        options.setProtoEvalModel(protoEvalModel + "</protoeval>\n" +
                "<currentaction>\n"
                + "   <param1>" + SIMPLIFICATION_STYLE + "</param1>\n"
                + "   <param2>deadcode</param2>\n"
                + "   <param3>off</param3>\n"
                + " </currentaction>\n"
                + "<protoeval>" + protoEvalModel);

        return options;
    }

    @Override
    protected List<AddressCandidate> storeDataCheck(PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.COPY)
            return null;

        if (getVerbose() > 0) {
            printf("* data check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // If output is a stack address, get the offset
        Varnode storeLoc = pcodeOpAST.getOutput();
        if (!storeLoc.getAddress().isStackAddress()) {
            return null;
        }

        long stackOffset = storeLoc.getAddress().getOffset();

        // Get all constant inputs to check for valid addresses
        Varnode dataToStore = pcodeOpAST.getInput(0);
        List<Long> constants = PcodeUtil.getConstantInputs(this, dataToStore);

        // Filter addresses
        List<AddressCandidate> results = new LinkedList<>();

        for (Long constant : constants) {
            Address addr;
            try {
                addr = PcodeUtil.addrFromLong(currentProgram, constant);
            } catch (AddressOutOfBoundsException e) {
                // Nothing to do if it's not a valid address
                continue;
            }

            // Check if the address is in a memory block where string data is stored.
            if (!getGolangInfo().isAddrInStringData(addr))
                continue;

            if (getVerbose() > 0) {
                printf("copy %s to addr. %s\n", addr.toString(), storeLoc.getAddress());
            }

            AddressCandidate result = new AddressCandidate(addr, stackOffset, pcodeOpAST);
            results.add(result);
        }

        if (results.isEmpty()) {
            return null;
        }

        return results;
    }

    @Override
    protected List<LengthCandidate> storeLenCheck(PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.COPY)
            return null;

        if (getVerbose() > 0) {
            printf("* length check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // If output is a stack address, get the offset
        Varnode storeLoc = pcodeOpAST.getOutput();
        if (!storeLoc.getAddress().isStackAddress()) {
            return null;
        }

        long stackOffset = storeLoc.getAddress().getOffset();

        // Get input, make sure it's a constant
        Varnode dataToStore = pcodeOpAST.getInput(0);
        List<Long> constants = PcodeUtil.getConstantInputs(this, dataToStore);

        // Filter constants
        List<LengthCandidate> results = new LinkedList<>();

        for (Long constantValue : constants) {
            // Simple string length bounds check
            if (constantValue < MIN_STR_LEN || constantValue > MAX_STR_LEN) {
                continue;
            }

            if (getVerbose() > 0) {
                printf("copy constant 0x%x to addr. %s\n",
                        constantValue,
                        storeLoc.getAddress());
            }

            LengthCandidate result = new LengthCandidate(constantValue.intValue(), stackOffset, pcodeOpAST);
            results.add(result);
        }

        if (results.isEmpty()) {
            return null;
        }

        return results;
    }

}
