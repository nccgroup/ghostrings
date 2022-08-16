//Same as GoDynamicStrings, but doesn't use the parallel decompiler.
//Use this if the parallel decompiler is exhausting system memory.
//
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

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghostrings.GhostringsUtil;

public class GoDynamicStringsSingle extends GoDynamicStrings {

    private DecompInterface decompIfc;

    private DecompInterface setUpDecompiler(String simplificationStyle) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options = makeDecompileOptions(state);

        decompInterface.setOptions(options);
        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.toggleParamMeasures(false);
        decompInterface.setSimplificationStyle(simplificationStyle);

        return decompInterface;
    }

    private HighFunction decompileFunction(Function func) {
        HighFunction highFunc = null;

        try {
            DecompileResults results = decompIfc.decompileFunction(
                    func,
                    decompIfc.getOptions().getDefaultTimeout(),
                    monitor);

            // Docs suggest calling this after every decompileFunction call
            decompIfc.flushCache();

            highFunc = results.getHighFunction();

            String decompError = results.getErrorMessage();
            if (decompError != null && decompError.length() > 0) {
                printf("Decompiler error for %s: %s\n", GhostringsUtil.funcNameAndAddr(func),
                        decompError.trim());
            }

            if (!results.decompileCompleted()) {
                printf("Decompilation not completed for %s\n", GhostringsUtil.funcNameAndAddr(func));
                return null;
            }
        } catch (Exception e) {
            println("Decompiler exception:");
            e.printStackTrace();
        }

        return highFunc;
    }

    @Override
    protected void analyzeFunctions(Iterator<Function> functions) throws Exception {
        decompIfc = setUpDecompiler(getSimplificationStyle());

        if (!decompIfc.openProgram(currentProgram)) {
            println("Decompiler could not open program");
            final String lastMsg = decompIfc.getLastMessage();
            if (lastMsg != null) {
                printf("Decompiler last message: %s\n", lastMsg);
            }
            decompIfc.stopProcess();
            return;
        }

        long progress = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();

            monitor.setMessage("Decompiling " + GhostringsUtil.getFuncName(func));

            HighFunction highFunc = decompileFunction(func);
            if (highFunc != null) {
                detectFunctionStrings(highFunc);
            }

            monitor.setProgress(++progress);
        }

        decompIfc.stopProcess();
    }

}
