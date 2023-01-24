package ghostrings;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class GolangProgramInfo {

    private final static Map<String, String> RODATA_BLOCK_NAMES;
    static {
        RODATA_BLOCK_NAMES = new HashMap<>();
        RODATA_BLOCK_NAMES.put(ElfLoader.ELF_NAME, ".rodata");
        RODATA_BLOCK_NAMES.put(PeLoader.PE_NAME, ".rdata");
        RODATA_BLOCK_NAMES.put(MachoLoader.MACH_O_NAME, "__rodata");
    }

    private final static Map<String, List<String>> GO_STRING_SYMBOLS;
    static {
        GO_STRING_SYMBOLS = new HashMap<>();
        GO_STRING_SYMBOLS.put(ElfLoader.ELF_NAME,
                Arrays.asList("go.string.*", "go:string.*"));
        GO_STRING_SYMBOLS.put(PeLoader.PE_NAME,
                Arrays.asList("go.string.*", "go:string.*"));
        GO_STRING_SYMBOLS.put(MachoLoader.MACH_O_NAME,
                Arrays.asList("_go.string.*", "_go:string.*"));
    }

    private final static Map<String, List<String>> GO_FUNC_SYMBOLS;
    static {
        GO_FUNC_SYMBOLS = new HashMap<>();
        GO_FUNC_SYMBOLS.put(ElfLoader.ELF_NAME,
                Arrays.asList("go.func.*", "go:func.*"));
        GO_FUNC_SYMBOLS.put(PeLoader.PE_NAME,
                Arrays.asList("go.func.*", "go:func.*"));
        GO_FUNC_SYMBOLS.put(MachoLoader.MACH_O_NAME,
                Arrays.asList("_go.func.*", "_go:func.*"));
    }

    private FlatProgramAPI flatProgramAPI;
    private boolean defaultExeFormatFallback;

    // Fields determined by program analysis
    private MemoryBlock roDataBlock;
    private List<Symbol> goStringSymbols;
    private List<Symbol> goFuncSymbols;
    private Address stringDataStart;
    private Address stringDataEnd;

    /**
     * Analyzes a Go binary to determine symbols, memory block names, and other
     * information that varies by the architecture, executable format, and/or Go
     * version.
     * 
     * @param flatProgramAPI     Flat program API for the program to analyze
     * @param allowDefaultFormat Whether to fall back to some default set of info if
     *                           the executable format is unrecognized
     * @throws Exception If critical information can't be determined
     */
    public GolangProgramInfo(FlatProgramAPI flatProgramAPI, boolean allowDefaultFormat) throws Exception {
        setFlatProgramAPI(flatProgramAPI);

        setDefaultExeFormatFallback(allowDefaultFormat);

        // Initial analysis
        determineRoDataBlock();
        determineGoSymbols();
        determineStringDataBounds();
    }

    private FlatProgramAPI getFlatProgramAPI() {
        return flatProgramAPI;
    }

    private void setFlatProgramAPI(FlatProgramAPI flatProgramAPI) {
        this.flatProgramAPI = flatProgramAPI;
    }

    public MemoryBlock getRoDataBlock() {
        return roDataBlock;
    }

    private void setRoDataBlock(MemoryBlock roDataBlock) {
        this.roDataBlock = roDataBlock;
    }

    public List<Symbol> getGoStringSymbols() {
        return goStringSymbols;
    }

    private void setGoStringSymbols(List<Symbol> goStringSymbols) {
        this.goStringSymbols = goStringSymbols;
    }

    public List<Symbol> getGoFuncSymbols() {
        return goFuncSymbols;
    }

    private void setGoFuncSymbols(List<Symbol> goFuncSymbols) {
        this.goFuncSymbols = goFuncSymbols;
    }

    public boolean isDefaultExeFormatFallback() {
        return defaultExeFormatFallback;
    }

    private void setDefaultExeFormatFallback(boolean defaultExeFormatFallback) {
        this.defaultExeFormatFallback = defaultExeFormatFallback;
    }

    public Address getStringDataStart() {
        return stringDataStart;
    }

    private void setStringDataStart(Address stringDataStart) {
        this.stringDataStart = stringDataStart;
    }

    public Address getStringDataEnd() {
        return stringDataEnd;
    }

    private void setStringDataEnd(Address stringDataEnd) {
        this.stringDataEnd = stringDataEnd;
    }

    private Program getProgram() {
        return getFlatProgramAPI().getCurrentProgram();
    }

    private String getExecutableFormat() {
        String exeFormat = getProgram().getExecutableFormat();

        // If the format is unknown, use something as a default
        if (exeFormat == null && isDefaultExeFormatFallback()) {
            // Default to names used in ELF
            exeFormat = ElfLoader.ELF_NAME;
        }

        return exeFormat;
    }

    /**
     * Find main read-only data block where string data is stored
     */
    private void determineRoDataBlock() {
        String exeFormat = getExecutableFormat();
        if (exeFormat == null) {
            return;
        }

        String roDataBlockName = RODATA_BLOCK_NAMES.get(exeFormat);
        if (roDataBlockName == null) {
            return;
        }

        MemoryBlock roBlock = getProgram().getMemory().getBlock(roDataBlockName);
        setRoDataBlock(roBlock);
    }

    /**
     * Find useful Go symbols according to the architecture and Go version.
     */
    private void determineGoSymbols() {
        String exeFormat = getExecutableFormat();
        if (exeFormat == null) {
            return;
        }

        // TODO: Use Go version info to select which symbols we expect
        // (go.string vs go:string)

        List<String> stringSymNames = GO_STRING_SYMBOLS.get(exeFormat);
        setGoStringSymbols(GhostringsUtil.findAllSymbols(getFlatProgramAPI(), stringSymNames));

        List<String> funcSymNames = GO_FUNC_SYMBOLS.get(exeFormat);
        setGoFuncSymbols(GhostringsUtil.findAllSymbols(getFlatProgramAPI(), funcSymNames));
    }

    /**
     * Use go.string.* - go.func.* as boundaries for the string data if possible.
     * Otherwise fall back to the read-only block start and/or end addresses.
     * @throws Exception If there's not enough info to determine start and end boundaries
     */
    private void determineStringDataBounds() throws Exception {
        Address start = null;
        Address end = null;

        List<Symbol> startSyms = getGoStringSymbols();
        List<Symbol> endSyms = getGoFuncSymbols();

        if (startSyms.size() == 1) {
            start = startSyms.get(0).getAddress();
        }

        if (endSyms.size() == 1) {
            end = endSyms.get(0).getAddress();
        }

        // Use rodata fallback if necessary
        if (start == null || end == null) {
            MemoryBlock roBlock = getRoDataBlock();
            if (roBlock == null) {
                throw new Exception("Can't determine boundaries for string data");
            }

            if (start == null) {
                start = roBlock.getStart();
            }

            if (end == null) {
                end = roBlock.getEnd();
            }
        }

        // go.string must come before go.func, and they're expected to be in the same
        // block
        if (GhostringsUtil.addrsInSameBlock(getProgram(), start, end) &&
                start.compareTo(end) < 0) {
            setStringDataStart(start);
            setStringDataEnd(end);
        } else {
            throw new Exception("String boundary addresses fail sanity check");
        }
    }

    /**
     * Use go.string boundary info if available to determine if potential string
     * address is located in go.string
     * 
     * @param addr Potential string address to check
     * @return True if the address doesn't violate known address boundaries
     */
    public boolean isAddrInStringData(Address addr) {
        Address start = getStringDataStart();
        Address end = getStringDataEnd();
        return addr.compareTo(start) >= 0 && addr.compareTo(end) < 0;
    }

}
