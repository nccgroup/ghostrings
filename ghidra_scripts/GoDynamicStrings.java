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
//This version uses the decompiler's "register" simplification style,
//which applies relatively few analysis rules. The resulting PCode output is
//more difficult to work with, but currently more reliable than the
//higher level version of the script.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding 
//@menupath 
//@toolbar 

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghostrings.AddressCandidate;
import ghostrings.GhostringsUtil;
import ghostrings.LengthCandidate;
import ghostrings.exceptions.DuplicateDataException;
import ghostrings.exceptions.UnhandledOpArgsException;
import ghostrings.exceptions.UnhandledOpTypeException;

public class GoDynamicStrings extends GhidraScript {

    protected final static String CHOICE_CUR_FUNC = "Selected function";
    protected final static String CHOICE_ALL_FUNCS = "All functions";

    protected final static long MIN_STR_LEN = 1;
    protected final static long MAX_STR_LEN = 0x4000;

    protected int verbose;
    protected final String printfPrefix = getScriptName().replace("%", "%%") + "> ";

    protected String getSimplificationStyle() {
        return "register";
    }

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

        return options;
    }

    protected static final class GoStringDecompConfigurer implements DecompileConfigurer {

        private DecompileOptions options;
        private String simplificationStyle;

        public GoStringDecompConfigurer(DecompileOptions options, String simplificationStyle) {
            this.options = options;
            this.simplificationStyle = simplificationStyle;
        }

        @Override
        public void configure(DecompInterface decompiler) {
            decompiler.setOptions(options);
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.toggleParamMeasures(false);
            decompiler.setSimplificationStyle(simplificationStyle);
        }

    }

    protected static final class GoStringDecompCallback extends DecompilerCallback<DecompileResults> {

        public GoStringDecompCallback(Program program, DecompileConfigurer configurer) {
            super(program, configurer);
        }

        @Override
        public DecompileResults process(DecompileResults results, TaskMonitor monitor1) throws Exception {
            if (monitor1.isCancelled()) {
                return null;
            }
            long progress = monitor1.getProgress() + 1;
            monitor1.setProgress(progress);

            return results;
        }

    }

    protected final class GoStringDecompConsumer implements Consumer<DecompileResults> {

        @Override
        public void accept(DecompileResults results) {
            if (results == null) {
                return;
            }

            Function func = results.getFunction();

            String decompError = results.getErrorMessage();
            if (decompError != null && decompError.length() > 0) {
                printf("Decompiler error for %s: %s\n", GhostringsUtil.funcNameAndAddr(func),
                        decompError.trim());
            }

            if (!results.decompileCompleted()) {
                printf("Decompilation not completed for %s\n", GhostringsUtil.funcNameAndAddr(func));
                return;
            }

            HighFunction highFunc = results.getHighFunction();
            detectFunctionStrings(highFunc);
        }

    }

    /** Make printf log prefix consistent with println */
    @Override
    public void printf(String message, Object... args) {
        super.printf(printfPrefix + message, args);
    }

    protected void printPcodeOp(PcodeOpAST pcodeOpAST) {
        printf("PcodeOp @ target 0x%x, order %02d, time 0x%02x: %s\n",
                pcodeOpAST.getSeqnum().getTarget().getOffset(),
                pcodeOpAST.getSeqnum().getOrder(),
                pcodeOpAST.getSeqnum().getTime(),
                pcodeOpAST.toString());
    }

    protected List<AddressCandidate> storeDataCheck(Program program, PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.STORE)
            return null;

        if (getVerbose() > 0) {
            printf("* data check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // If output is a stack address, get the offset
        Varnode storeLoc = pcodeOpAST.getInput(1);

        Long stackOffset = null;
        try {
            stackOffset = GhostringsUtil.outputStackOffset(program, storeLoc);
        } catch (UnhandledOpTypeException | UnhandledOpArgsException e) {
            println(e.getMessage());
        }

        if (stackOffset == null) {
            return null;
        }

        // Get all constant inputs to check for valid addresses
        Varnode dataToStore = pcodeOpAST.getInput(2);
        List<Long> constants = GhostringsUtil.getConstantInputs(this, dataToStore);

        // Filter addresses
        List<AddressCandidate> results = new LinkedList<>();

        for (Long constant : constants) {
            Address addr;
            try {
                addr = GhostringsUtil.addrFromLong(program, constant);
            } catch (AddressOutOfBoundsException e) {
                // Nothing to do if it's not a valid address
                continue;
            }

            // Check if the address is in a memory block where string data is stored.
            if (!GhostringsUtil.isAddrInStringMemBlock(program, addr))
                continue;

            if (getVerbose() > 0) {
                Address destAddr = GhostringsUtil.getLoadStoreAddr(pcodeOpAST, program.getAddressFactory());
                printf("copy %s to addr. %s\n", addr.toString(), destAddr.toString(true));
            }

            AddressCandidate result = new AddressCandidate(addr, stackOffset, pcodeOpAST);
            results.add(result);
        }

        if (results.isEmpty()) {
            return null;
        }

        return results;
    }

    protected List<LengthCandidate> storeLenCheck(Program program, PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.STORE)
            return null;

        if (getVerbose() > 0) {
            printf("* length check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // If output is a stack address, get the offset
        Varnode storeLoc = pcodeOpAST.getInput(1);

        Long stackOffset = null;
        try {
            stackOffset = GhostringsUtil.outputStackOffset(program, storeLoc);
        } catch (UnhandledOpTypeException | UnhandledOpArgsException e) {
            println(e.getMessage());
        }

        if (stackOffset == null) {
            if (getVerbose() > 1)
                println("Couldn't get an SP offset for the output varnode");
            return null;
        }

        // Get input, make sure it's a constant
        Varnode dataToStore = pcodeOpAST.getInput(2);

        List<Long> constants = GhostringsUtil.getConstantInputs(this, dataToStore);
        if (constants.isEmpty()) {
            return null;
        }

        // Filter constants
        List<LengthCandidate> results = new LinkedList<>();

        for (Long constant : constants) {
            // Simple string length bounds check
            if (constant < MIN_STR_LEN || constant > MAX_STR_LEN) {
                continue;
            }

            if (getVerbose() > 0) {
                Address destAddr = GhostringsUtil.getLoadStoreAddr(pcodeOpAST, program.getAddressFactory());

                printf("copy constant 0x%x to addr. %s\n",
                        constant,
                        destAddr.toString(true));
            }

            LengthCandidate result = new LengthCandidate(constant.intValue(), stackOffset, pcodeOpAST);
            results.add(result);
        }

        if (results.isEmpty()) {
            return null;
        }

        return results;
    }

    protected String checkForString(AddressCandidate addrCandidate, LengthCandidate lenCandidate) {
        final int ptrSize = currentProgram.getDefaultPointerSize();

        // Length value should be right after the address on the stack
        if (lenCandidate.getStackOffset() - addrCandidate.getStackOffset() != ptrSize) {
            return null;
        }

        return GhostringsUtil.checkForString(
                currentProgram,
                addrCandidate.getStringAddr(),
                lenCandidate.getStringLength());
    }

    protected void detectFunctionStrings(HighFunction highFunc) {
        Function func = highFunc.getFunction();

        if (getVerbose() > 0)
            printf("local dynamic string header analysis of %s\n", GhostringsUtil.funcNameAndAddr(func));

        List<AddressCandidate> storeData = null;
        List<LengthCandidate> storeLen = null;
        List<LengthCandidate> storeLenOld = null;

        /*
         * TODO: For main analysis loop, need to consider that a single Pcode op can
         * generate multiple address/length candidates in order to handle MULTIEQUAL.
         * 
         * There can also be pointers to string structs in .rodata, which could be
         * handled as a single op producing an address and length candidate. (Or handled
         * with a separate script for static string structs.)
         */

        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (getVerbose() > 1)
                printPcodeOp(pcodeOpAST);

            boolean opIdentified = false;

            // Check for string address or length store
            // Currently returns null or list with values, no empty list
            List<AddressCandidate> addrCheck = storeDataCheck(currentProgram, pcodeOpAST);
            if (addrCheck != null) {
                opIdentified = true;
                storeData = addrCheck;

                // Only keep track of one length store that came before the address store
                if (storeLen != null) {
                    storeLenOld = storeLen;
                    storeLen = null;
                }
            } else {
                List<LengthCandidate> lenCheck = storeLenCheck(currentProgram, pcodeOpAST);
                if (lenCheck != null) {
                    opIdentified = true;
                    if (storeLen != null) {
                        storeLenOld = storeLen;
                    }
                    storeLen = lenCheck;
                }
            }

            // funcCallCheck was here to test working with calls that ate up stack variables

            if (!opIdentified) {
                // Nothing new to check found
                continue;
            }

            // When an address and length are set, check for string
            if (storeData != null && storeLen != null) {
                boolean hasFinds = tryCandidates(storeData, storeLen);
                if (hasFinds) {
                    // clear current possible length if it's used
                    storeLen = null;
                } else if (storeLenOld != null) {
                    // Try with length op before address op
                    hasFinds = tryCandidates(storeData, storeLenOld);
                }

                if (hasFinds) {
                    storeData = null;
                    storeLenOld = null;
                }
            }
        }

        if (getVerbose() > 0)
            printf("exit analysis of %s\n", GhostringsUtil.funcNameAndAddr(func));
    }

    /**
     * Use list of one or more address candidates with list of one or more length candidates
     * to attempt to find string data.
     * @param addresses Non-empty address candidate list
     * @param lengths Non-empty length candidate list
     * @return Whether any strings were found
     */
    protected boolean tryCandidates(List<AddressCandidate> storeData, List<LengthCandidate> storeLen) {
        boolean hasFinds = false;

        if (storeLen.size() == 1 && !storeData.isEmpty()) {
            // One length value, one or many addresses.
            // - Could be multiple strings with the same length.
            LengthCandidate lengthCandidate = storeLen.get(0);

            for (AddressCandidate curAddr : storeData) {
                String checkString = checkForString(curAddr, lengthCandidate);
                if (checkString != null) {
                    Address stringAddr = curAddr.getStringAddr();
                    // When a string is found, always clear possible address and old possible length
                    hasFinds = true;
                    tryDefString(stringAddr, checkString);
                }
            }
        } else if (storeLen.size() > 1 && storeData.size() == 1) {
            // Many length values, one address value.
            // - Not sure if there's a valid case for this,
            //   so check for maximum working length value.
            AddressCandidate addressCandidate = storeData.get(0);

            // Sort lengths in descending order
            storeLen.sort((l1, l2) -> {
                return Long.compare(l2.getStringLength(),
                        l1.getStringLength());
            });

            for (LengthCandidate curLen : storeLen) {
                String checkString = checkForString(addressCandidate, curLen);
                if (checkString != null) {
                    Address stringAddr = addressCandidate.getStringAddr();
                    // When a string is found, always clear possible address and old possible length
                    hasFinds = true;
                    tryDefString(stringAddr, checkString);
                    break;
                }
            }
        } else if (storeLen.size() > 1 && storeData.size() > 1) {
            // Many length values, many address values.
            // - Could be multiple strings with different lengths.
            // Can take advantage of the string ordering to help somewhat.

            if (storeLen.size() == storeData.size()) {
                // Put both lists in descending order
                storeLen.sort((l1, l2) -> {
                    return Long.compare(l2.getStringLength(),
                            l1.getStringLength());
                });

                storeData.sort((l1, l2) -> {
                    return l2.getStringAddr().compareTo(l1.getStringAddr());
                });

                for (int i = 0; i < storeLen.size(); i++) {
                    AddressCandidate addr = storeData.get(i);
                    LengthCandidate len = storeLen.get(i);

                    String checkString = checkForString(addr, len);
                    if (checkString != null) {
                        Address stringAddr = addr.getStringAddr();
                        // When a string is found, always clear possible address and old possible length
                        hasFinds = true;
                        tryDefString(stringAddr, checkString);
                    }
                }
            } else {
                // TODO what if the number of lengths and addrs don't match? do non-unique
                // lengths get consolidated?
                printf("mismatched number of lens (%d) and addrs (%d)\n",
                        storeLen.size(), storeData.size());
            }
        }

        return hasFinds;
    }

    /**
     * Attempt to create the string definition and print a description of what
     * happens.
     */
    protected void tryDefString(Address stringAddr, String checkString) {
        final String strDesc = String.format("@ %s: \"%s\"",
                stringAddr.toString(),
                StringUtilities.convertControlCharsToEscapeSequences(checkString));
        try {
            boolean defineSucceeded = GhostringsUtil.tryDefString(
                    this, stringAddr, checkString, getVerbose());
            if (defineSucceeded) {
                println("* Define succeeded " + strDesc);
            } else {
                println("* Define failed " + strDesc);
            }
        } catch (DuplicateDataException e) {
            // This exact string is already defined
            println("* Already defined " + strDesc);
        } catch (Exception e) {
            // removeData just throws Exception :\
            println("* Define failed with exception: " + e.getMessage());
        }
    }

    protected String askTargetChoice() throws CancelledException {
        final List<String> choices = Arrays.asList(CHOICE_CUR_FUNC, CHOICE_ALL_FUNCS);

        return askChoice("Go String Analyzer Mode",
                "Analyze currently selected function or all functions?",
                choices,
                CHOICE_CUR_FUNC);
    }

    protected void analyzeFunctions(Iterator<Function> functions) throws Exception {
        DecompileOptions opts = makeDecompileOptions(state);
        GoStringDecompConfigurer configurer = new GoStringDecompConfigurer(opts, getSimplificationStyle());
        GoStringDecompCallback callback = new GoStringDecompCallback(currentProgram, configurer);
        GoStringDecompConsumer consumer = new GoStringDecompConsumer();

        ParallelDecompiler.decompileFunctions(
                callback, currentProgram, functions, consumer, monitor);

        callback.dispose();
    }

    public void run() throws Exception {
        setVerbose(0);

        println("Start Go string finder");

        // Ask user to analyze selected function or all functions
        final String selectedMode;
        try {
            selectedMode = askTargetChoice();
        } catch (CancelledException e) {
            println("Script cancelled");
            return;
        }

        if (CHOICE_ALL_FUNCS.equals(selectedMode)) {
            // Iterate all functions
            int funcCount = currentProgram.getFunctionManager().getFunctionCount();
            monitor.setMaximum(funcCount);
            monitor.setProgress(0);
            monitor.setIndeterminate(false);

            FunctionIterator fIter = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
            analyzeFunctions(fIter);
        } else {
            // Check currently selected function
            Function func = getFunctionContaining(currentAddress);
            if (func == null) {
                final String msg = "No function selected";
                println(msg);
                popup(msg);
            } else {
                monitor.setIndeterminate(true);
                monitor.setMessage("Analyzing " + GhostringsUtil.getFuncName(func));
                println("Analyzing function " + GhostringsUtil.funcNameAndAddr(func));
                analyzeFunctions(Arrays.asList(func).iterator());
            }
        }
    }

    protected int getVerbose() {
        return verbose;
    }

    protected void setVerbose(int verbose) {
        this.verbose = verbose;
    }

}
