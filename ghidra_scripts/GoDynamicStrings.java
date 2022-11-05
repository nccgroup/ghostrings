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
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
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
import ghidra.program.model.listing.Data;
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
    protected final static Set<String> STR_MEM_BLOCKS;
    static {
        STR_MEM_BLOCKS = new HashSet<>();
        STR_MEM_BLOCKS.add(".rodata"); // ELF
        STR_MEM_BLOCKS.add(".rdata"); // PE
        STR_MEM_BLOCKS.add("__rodata"); // Mach-O
    }

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

    protected AddressCandidate storeDataCheck(Program program, PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.STORE)
            return null;

        if (getVerbose() > 0) {
            printf("* data check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // Get input, make sure it's a valid address
        Varnode dataToStore = pcodeOpAST.getInput(2);

        Address candidateAddr = null;

        if (dataToStore.isConstant()) {
            // Constant may be an address
            candidateAddr = GhostringsUtil.addrFromConstant(program, dataToStore);
        } else if (dataToStore.isRegister()) {
            // Register may hold an address
            PcodeOp def = dataToStore.getDef();
            // Check for LOAD op that loaded an address into the register,
            // e.g. getting address from constant pool in ARM 32
            if (def != null && def.getOpcode() == PcodeOp.LOAD) {
                Address loadFrom = GhostringsUtil.getLoadStoreAddr(def, program.getAddressFactory());
                Data dataLoaded = getDataAt(loadFrom);
                if (dataLoaded != null && dataLoaded.isPointer()) {
                    candidateAddr = (Address) dataLoaded.getValue();
                }
            }
        }

        if (candidateAddr == null) {
            return null;
        }

        // Check if the address is in .rodata
        String blockName = GhostringsUtil.memBlockName(program, candidateAddr);
        if (!STR_MEM_BLOCKS.contains(blockName))
            return null;

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

        if (getVerbose() > 0) {
            Address destAddr = GhostringsUtil.getLoadStoreAddr(pcodeOpAST, program.getAddressFactory());
            printf("copy %s to addr. %s\n", candidateAddr.toString(), destAddr.toString(true));
        }

        AddressCandidate result = new AddressCandidate(candidateAddr, stackOffset, pcodeOpAST);
        return result;
    }

    protected LengthCandidate storeLenCheck(Program program, PcodeOpAST pcodeOpAST) {
        if (pcodeOpAST.getOpcode() != PcodeOp.STORE)
            return null;

        if (getVerbose() > 0) {
            printf("* length check: pcode store op @ %x : seq %d\n",
                    pcodeOpAST.getSeqnum().getTarget().getOffset(),
                    pcodeOpAST.getSeqnum().getOrder());
        }

        // Get input, make sure it's a constant
        Varnode dataToStore = pcodeOpAST.getInput(2);
        if (!dataToStore.isConstant())
            return null;

        long constantValue = dataToStore.getAddress().getOffset();

        // Simple string length bounds check
        if (constantValue < MIN_STR_LEN || constantValue > MAX_STR_LEN) {
            return null;
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

        if (getVerbose() > 0) {
            Address destAddr = GhostringsUtil.getLoadStoreAddr(pcodeOpAST, program.getAddressFactory());

            printf("copy constant 0x%x to addr. %s\n",
                    constantValue,
                    destAddr.toString(true));
        }

        LengthCandidate result = new LengthCandidate((int) constantValue, stackOffset, pcodeOpAST);
        return result;
    }

    protected String checkForString(AddressCandidate addrCandidate, LengthCandidate lenCandidate) {
        final int ptrSize = currentProgram.getDefaultPointerSize();

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

        AddressCandidate storeData = null;
        LengthCandidate storeLen = null;
        LengthCandidate storeLenOld = null;

        /*
         * TODO: For main analysis loop, need to consider that a single Pcode op can
         * generate multiple address/length candidates in order to handle MULTIEQUAL.
         * There can also be pointers to string structs in .rodata, which could be
         * handled as a single op producing an address and length candidate.
         */

        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (getVerbose() > 1)
                printPcodeOp(pcodeOpAST);

            boolean opIdentified = false;

            // Check for string address or length store
            AddressCandidate addrCheck = storeDataCheck(currentProgram, pcodeOpAST);
            if (addrCheck != null) {
                opIdentified = true;
                storeData = addrCheck;

                // Only keep track of one length store that came before the address store
                if (storeLen != null) {
                    storeLenOld = storeLen;
                    storeLen = null;
                }
            } else {
                LengthCandidate lenCheck = storeLenCheck(currentProgram, pcodeOpAST);
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
                // Try with length op after address op
                String checkString = checkForString(storeData, storeLen);
                if (checkString != null) {
                    // clear current possible length if it's used
                    storeLen = null;
                } else if (storeLenOld != null) {
                    // Try with length op before address op
                    checkString = checkForString(storeData, storeLenOld);
                }

                if (checkString != null) {
                    Address stringAddr = storeData.getStringAddr();
                    // When a string is found, always clear possible address and old possible length
                    storeData = null;
                    storeLenOld = null;

                    tryDefString(stringAddr, checkString);
                }
            }

        }

        if (getVerbose() > 0)
            printf("exit analysis of %s\n", GhostringsUtil.funcNameAndAddr(func));
    }

    /** Attempt to create the string definition and print a description of what happens. */
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
