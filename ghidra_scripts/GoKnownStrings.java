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
//Searches for standard unique strings and defines them.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.StringUtilities;

public class GoKnownStrings extends GhidraScript {

    private final static class KnownString {
        final String name;
        final String value;

        public KnownString(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    private static final List<KnownString> KNOWN_STRINGS;
    static {
        KNOWN_STRINGS = new ArrayList<>();

        // This 200 byte string from strconv/itoa.go is often near the end of go.string.
        KNOWN_STRINGS.add(new KnownString(
                "strconv/itoa.go:smallsString",
                "00010203040506070809" +
                "10111213141516171819" +
                "20212223242526272829" +
                "30313233343536373839" +
                "40414243444546474849" +
                "50515253545556575859" +
                "60616263646566676869" +
                "70717273747576777879" +
                "80818283848586878889" +
                "90919293949596979899"
                ));

        // Also from strconv/itoa.go; not as unique
        KNOWN_STRINGS.add(new KnownString(
                "strconv/itoa.go:digits",
                "0123456789abcdefghijklmnopqrstuvwxyz"
                ));

        // leftcheats cutoff strings
        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_22",
                "2384185791015625"
            ));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_23",
                "11920928955078125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_24",
                "59604644775390625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_25",
                "298023223876953125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_26",
                "1490116119384765625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_27",
                "7450580596923828125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_28",
                "37252902984619140625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_29",
                "186264514923095703125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_30",
                "931322574615478515625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_31",
                "4656612873077392578125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_32",
                "23283064365386962890625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_33",
                "116415321826934814453125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_34",
                "582076609134674072265625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_35",
                "2910383045673370361328125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_36",
                "14551915228366851806640625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_37",
                "72759576141834259033203125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_38",
                "363797880709171295166015625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_39",
                "1818989403545856475830078125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_40",
                "9094947017729282379150390625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_41",
                "45474735088646411895751953125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_42",
                "227373675443232059478759765625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_43",
                "1136868377216160297393798828125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_44",
                "5684341886080801486968994140625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_45",
                "28421709430404007434844970703125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_46",
                "142108547152020037174224853515625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_47",
                "710542735760100185871124267578125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_48",
                "3552713678800500929355621337890625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_49",
                "17763568394002504646778106689453125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_50",
                "88817841970012523233890533447265625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_51",
                "444089209850062616169452667236328125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_52",
                "2220446049250313080847263336181640625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_53",
                "11102230246251565404236316680908203125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_54",
                "55511151231257827021181583404541015625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_55",
                "277555756156289135105907917022705078125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_56",
                "1387778780781445675529539585113525390625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_57",
                "6938893903907228377647697925567626953125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_58",
                "34694469519536141888238489627838134765625"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_59",
                "173472347597680709441192448139190673828125"));

        KNOWN_STRINGS.add(new KnownString(
                "strconv/decimal.go:leftcheats_60",
                "867361737988403547205962240695953369140625"));
    }

    private final boolean verbose = false;
    private final String printfPrefix = getScriptName().replace("%", "%%") + "> ";

    /** Make printf log prefix consistent with println */
    @Override
    public void printf(String message, Object... args) {
        super.printf(printfPrefix + message, args);
    }

    private void printStringData(Data data) {
        final String strData = (String) data.getValue();
        printf("%s, %d:\t\"%s\"\n",
                data.getAddress(),
                data.getLength(),
                StringUtilities.convertControlCharsToEscapeSequences(strData));
    }

    /**
     * Find string data after a start address and define it. Clears any conflicting
     * data.
     */
    private Data findAndDefineString(Address startAddr, String target) {
        Address result = findBytes(startAddr, target);
        if (result == null) {
            if (verbose) {
                println("Target string not found");
            }
            return null;
        }

        Data conflict = getDataAt(result);
        if (conflict != null &&
                conflict.hasStringValue() &&
                target.equals(conflict.getValue())) {
            // Already defined
            return null;
        }

        if (verbose) {
            printf("Found target string @ %s\n", result);
        }

        // Clear all conflicting data defined within the string
        Address endAddr = result.add(target.length());
        try {
            while (conflict != null && conflict.getAddress().compareTo(result) > -1) {
                removeData(conflict);
                conflict = getDataBefore(endAddr);
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

        try {
            return createAsciiString(result, target.length());
        } catch (CodeUnitInsertionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    @Override
    protected void run() throws Exception {
        List<Symbol> results = getSymbols("go.string.*", null);
        if (results.size() != 1) {
            final String msg = "Want a single go.string.* symbol, found " + results.size();
            println(msg);
            popup(msg);
            return;
        }

        Symbol goStringsBlob = results.get(0);
        Address blobAddr = goStringsBlob.getAddress();
        println("go.string.* @ " + blobAddr);

        for (KnownString knownString : KNOWN_STRINGS) {
            Data strData = findAndDefineString(blobAddr, knownString.value);
            if (strData != null) {
                println("Found and defined " + knownString.name);
                printStringData(strData);
            }
        }
    }
}
