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
//Fill in undefined strings based on the fact that they are defined in order of increasing length.
//For a stripped binary, one should first manually create the go.string.* (or _go.string.* in Mach-O) label at the likely start location.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.StringUtilities;
import ghostrings.GhostringsUtil;

public class GoStringFiller extends GhidraScript {

    private final boolean verbose = false;
    private final String printfPrefix = getScriptName().replace("%", "%%") + "> ";

    private boolean allowFalsePositives = false;
    private boolean autoClearShortStrings = false;

    private static long calcGapLength(Data left, Data right) {
        return right.getAddress().getOffset() - (left.getAddress().getOffset() + left.getLength());
    }

    /** Make printf log prefix consistent with println */
    @Override
    public void printf(String message, Object... args) {
        super.printf(printfPrefix + message, args);
    }

    private void fillRange(Address start, Address end, int length) {
        // start addr must be less than end addr
        if (start.compareTo(end) >= 0)
            return;

        Address curAddr = start;

        while (curAddr.getOffset() < end.getOffset()) {
            Data data = getDataAt(curAddr);
            if (data == null) {
                try {
                    String newStr = (String) createAsciiString(curAddr, length).getValue();
                    printf("defined @ %s: \"%s\"\n",
                            curAddr.toString(),
                            StringUtilities.convertControlCharsToEscapeSequences(newStr));
                } catch (CodeUnitInsertionException e) {
                    println(e.getMessage());
                }
            }

            curAddr = curAddr.add(length);
        }
    }

    private void fillCount(Address start, int length, int count) {
        if (count == 0 || length == 0) {
            throw new IllegalArgumentException();
        }

        Address end = start.add(count * length);
        fillRange(start, end, length);
    }

    /**
     * Check if a gap between defined strings can be filled with strings of all the
     * same length.
     * 
     * NOTE: Allows false positives if there are strings of different lengths inside
     * the gap, not just strings of all the same length. See
     * {@link #findSplitLengths}.
     * 
     * @param dataAt    String data on the left
     * @param dataAfter String data on the right
     * @return True if it fills the gap with defined strings, false if not.
     */
    private boolean findUniqueDivisor(Data dataAt, Data dataAfter) {
        long gapLen = calcGapLength(dataAt, dataAfter);

        if (gapLen <= 0) {
            // No gap
            return false;
        }

        if (verbose) {
            printf("gap of %d between %s and %s\n",
                    gapLen,
                    dataAt.getAddress(),
                    dataAfter.getAddress());
        }

        boolean success = false;
        int uniqueDiv = 0;
        int rangeMin = dataAt.getLength();
        int rangeMax = dataAfter.getLength();

        for (int testDiv = rangeMin; testDiv <= rangeMax; testDiv++) {
            if (gapLen % testDiv == 0) {
                if (uniqueDiv != 0) {
                    if (verbose) {
                        println("Couldn't pick unique divisor");
                    }
                    success = false;
                    break;
                }
                uniqueDiv = testDiv;
                success = true;
            }
        }

        if (success) {
            if (verbose) {
                printf("Unique divisor %d can make %d strings\n", uniqueDiv, gapLen / uniqueDiv);
            }
            Address startAt = dataAt.getAddress().add(dataAt.getLength());
            fillRange(startAt, dataAfter.getAddress(), uniqueDiv);
        }

        return success;
    }

    private List<List<Integer>> splitLengthCandidates(int x, int y, long gapLen) {
        List<List<Integer>> candidates = new ArrayList<>();

        // Special case if left/right length are the same
        if (x == y) {
            if (gapLen % x == 0) {
                candidates.add(Arrays.asList((int) (gapLen / x), 0));
            }
            return candidates;
        }

        long max_count_y = Math.floorDiv(gapLen, y);
        for (long count_y = max_count_y; count_y >= 0; count_y--) {
            long remainder = gapLen - y * count_y;
            if (remainder % x == 0) {
                long count_x = remainder / x;
                candidates.add(Arrays.asList((int) count_x, (int) count_y));
            }
        }

        return candidates;
    }

    /**
     * Gap could have strings of different lengths in it. There could be multiple
     * possibilities for a combination of lengths, or just one possibility. If there
     * is a unique combination of lengths, this method will define strings based on
     * those lengths and return true. Otherwise, it returns false.
     * 
     * NOTE: This currently only handles up to two different lengths of strings in
     * the gap. Need to handle more than two lengths at a time to ensure there are
     * no alternate possibilities when the difference between leftLen and rightLen
     * is greater than 1.
     * 
     * For example, between 1 and 2 length strings, a gap of size 3 could be:
     * [1, {1, 1, 1}, 2]
     * or
     * [1, {1, 2}, 2]
     * 
     * There can also be unique combinations, such as:
     * [3, (gapLen=7), 4] must be [3, {3, 4}, 4]
     * 
     * @param left  String data on the left
     * @param right String data on the right
     * @return True if a unique combination of lengths was discovered, false if not.
     */
    private boolean findSplitLengths(Data left, Data right) {
        long gapLen = calcGapLength(left, right);

        if (gapLen <= 0) {
            // No gap
            return false;
        }

        List<List<Integer>> candidates = splitLengthCandidates(
                left.getLength(), right.getLength(), gapLen);

        if (candidates.size() != 1) {
            // No unique result
            return false;
        }

        List<Integer> counts = candidates.get(0);
        int count_x = counts.get(0);
        int count_y = counts.get(1);

        Address startLeft = left.getAddress().add(left.getLength());
        Address startRight = startLeft.add(count_x * left.getLength());

        if (count_x > 0) {
            fillCount(startLeft, left.getLength(), count_x);
        }

        if (count_y > 0) {
            fillCount(startRight, right.getLength(), count_y);
        }

        return true;
    }

    /**
     * Minimum size of two strings in a gap is left_len*2. If the gap length is less
     * than that (as well as the length of the next string), it must be one string.
     * 
     * @param left  String data on the left
     * @param right String data on the right
     * @return True if it fills the gap with defined strings, false if not.
     */
    private boolean findOneIntermediary(Data left, Data right) {
        long gapLen = calcGapLength(left, right);

        if (gapLen <= 0) {
            return false;
        }

        if (gapLen < (left.getLength() * 2) && gapLen <= right.getLength()) {
            Address startAddr = left.getAddress().add(left.getLength());
            fillRange(startAddr, right.getAddress(), (int) gapLen);
            return true;
        }

        return false;
    }

    /**
     * Should be able to identify two of the smallest possible pairs of strings: two
     * leftLen size strings, or a leftLen and leftLen+1 size string. The rightLen
     * must be smaller than the gap size, or else there could also be a single
     * string that fills the entire gap.
     * 
     * @param left  String data on the left
     * @param right String data on the right
     * @return True if it fills the gap with defined strings, false if not.
     */
    private boolean findTwoIntermediaries(Data left, Data right) {
        long gapLen = calcGapLength(left, right);

        if (gapLen <= 0) {
            return false;
        }

        int leftLen = left.getLength();
        int rightLen = right.getLength();

        if (leftLen > 1 && gapLen > rightLen) {
            if (gapLen == leftLen * 2) {
                // it's 2 leftLen strings
                Address startAddr = left.getAddress().add(leftLen);
                fillCount(startAddr, leftLen, 2);
                return true;
            } else if (gapLen == leftLen * 2 + 1) {
                // it's a leftLen string, then a leftLen+1 string
                Address startAddr = left.getAddress().add(leftLen);
                fillCount(startAddr, leftLen, 1);
                fillCount(startAddr.add(leftLen), leftLen + 1, 1);
                return true;
            }
        }

        return false;
    }

    private void printStringData(Data data) {
        final String strData = (String) data.getValue();
        printf("%s, %d:\t\"%s\"\n",
                data.getAddress(),
                data.getLength(),
                StringUtilities.convertControlCharsToEscapeSequences(strData));
    }

    @Override
    protected void run() throws Exception {
        final String goStringSym = GhostringsUtil.goStringSymbol(currentProgram);
        List<Symbol> results = getSymbols(goStringSym, null);
        if (results.size() != 1) {
            final String msg = String.format(
                    "Want a single %s symbol, found %d", goStringSym, results.size());
            println(msg);
            popup(msg);
            return;
        }

        autoClearShortStrings = askYesNo(
                "Automatically clear short strings?",
                "Automatically clear a defined string if it violates the\n" +
                "ascending length order of go.string.*?");

        allowFalsePositives = askYesNo(
                "Allow false positives?",
                "Assume gaps in go.string.* are filled with strings of\n" +
                "all the same length (if unique length values can't be determined),\n" +
                "which could result in false positives?");

        Symbol goStringsBlob = results.get(0);
        printf("%s @ %s\n", goStringSym, goStringsBlob.getAddress());

        Address curAddr = goStringsBlob.getAddress();
        while (!monitor.isCancelled()) {
            Data dataAt = getDataAt(curAddr);
            Data dataAfter = getDataAfter(curAddr);

            if (dataAfter == null) {
                println("no more data definitions");
                break;
            } else if (!dataAfter.hasStringValue()) {
                DataType dType = dataAfter.getDataType();
                if (Undefined.isUndefined(dType)) {
                    removeData(dataAfter);
                    // Restart the loop
                    continue;
                }
                println("reached non-string data @ " + dataAfter.getAddress());
                // TODO go.func.* might also be a good marker for the end of go.string.*
                break;
            } else if (dataAt != null && dataAt.hasStringValue()) {
                if (verbose) {
                    printStringData(dataAt);
                }

                if (dataAfter.getLength() < dataAt.getLength()) {
                    // Shouldn't happen within the blob; usually a string declared
                    // with too short a length. Easy to manually clear and re-run.
                    println("reached smaller string @ " + dataAfter.getAddress());
                    if (!verbose)
                        printStringData(dataAfter);
                    if (autoClearShortStrings) {
                        removeData(dataAfter);
                        continue;
                    }
                    break;
                }

                // Check if a group of strings can be found based on gap between defined strings
                boolean success = false;
                if (dataAfter.getLength() - dataAt.getLength() <= 1) {
                    success = findSplitLengths(dataAt, dataAfter);
                }

                if (!success) {
                    success = findOneIntermediary(dataAt, dataAfter);
                }

                if (!success) {
                    // Not tested as much
                    success = findTwoIntermediaries(dataAt, dataAfter);
                }

                if (!success && allowFalsePositives) {
                    // Currently assumes the gap is filled with strings of all the same length,
                    // but there could be strings of different lengths in between.
                    success = findUniqueDivisor(dataAt, dataAfter);
                }
            }

            curAddr = dataAfter.getAddress();
        }
    }
}
