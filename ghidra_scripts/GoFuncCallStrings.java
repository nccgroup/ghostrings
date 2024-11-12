/* ###
 * Ghostrings
 * Copyright (C) 2024  NCC Group
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
//Find dynamic Go string structures passed via registers rather than
//allocated on the stack (P-Code based).
//Clearing out all automatically defined strings in .rodata/.rdata/__rodata first is recommended.
//The built-in ASCII Strings analysis can then be run again afterwards,
//with the option to clear existing strings disabled.
//
//This version uses the "normalize" simplification to find string address/length values
//never written to the stack, just passed directly through registers to a function call.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghostrings.AddressCandidate;
import ghostrings.CandidateGroup;
import ghostrings.GhostringsUtil;
import ghostrings.LengthCandidate;
import ghostrings.PcodeUtil;

public class GoFuncCallStrings extends GoDynamicStrings {

    private static final String SIMPLIFICATION_STYLE = "normalize";

    @Override
    protected String getSimplificationStyle() {
        return SIMPLIFICATION_STYLE;
    }

    protected List<CandidateGroup> callParamsCheck(PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.CALL)
            return null;

        if (getVerbose() > 0) {
            printf("* check: pcode call op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        List<CandidateGroup> results = new ArrayList<>();
        List<AddressCandidate> addrCandidates = new ArrayList<>();
        List<LengthCandidate> lenCandidates = new ArrayList<>();

        for (Varnode input: pcodeOpAST.getInputs()) {
            List<Long> constants = PcodeUtil.getConstantInputs(this, input);
            if (constants.isEmpty()) {
                continue;
            }

            List<Address> addrs = filterAddressConstants(constants);
            if (!addrs.isEmpty()) {
                addrCandidates.addAll(addrs.stream()
                        .map(addr -> new AddressCandidate(addr, 0xdeadbeef, pcodeOpAST))
                        .collect(Collectors.toList()));
                constants.removeAll(addrs.stream()
                        .map(addr -> addr.getOffset())
                        .collect(Collectors.toList()));
            }

            List<Integer> lens = filterLengthConstants(constants);
            if (!lens.isEmpty()) {
                lenCandidates.addAll(lens.stream()
                        .map(len -> new LengthCandidate(len, 0xdeadbeef, pcodeOpAST))
                        .collect(Collectors.toList()));
            }
        }

        if (!addrCandidates.isEmpty() && !lenCandidates.isEmpty()) {
            results.add(new CandidateGroup(addrCandidates, lenCandidates));
        }

        if (results.isEmpty()) {
            return null;
        }

        return results;
    }

    @Override
    protected void detectFunctionStrings(HighFunction highFunc) {
        Function func = highFunc.getFunction();

        if (!currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().contains("golang")) {
            final String warning = "WARNING: Program not loaded as golang binary; function call arguments may not be detected";
            popup(warning);
            println(warning);
        }

        if (getVerbose() > 0)
            printf("local dynamic string header analysis of %s\n", GhostringsUtil.funcNameAndAddr(func));

        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (getVerbose() > 1)
                printPcodeOp(pcodeOpAST);

            List<CandidateGroup> groups = callParamsCheck(pcodeOpAST);
            if (groups == null) {
                continue;
            }

            for (CandidateGroup group: groups) {
                tryCandidateGroup(group);
            }
        }

        if (getVerbose() > 0)
            printf("exit analysis of %s\n", GhostringsUtil.funcNameAndAddr(func));
    }

}
