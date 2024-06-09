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
//String data is loaded from data/known_strings.json.
//@author James Chambers <james.chambers@nccgroup.com>
//@category Golang
//@keybinding
//@menupath
//@toolbar

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghostrings.GolangProgramInfo;

public class GoKnownStrings extends GhidraScript {

    private final static class KnownString {
        final String name;
        final String value;
        final String comment;

        @SuppressWarnings("unused")
        public KnownString(String name, String value) {
            this.name = name;
            this.value = value;
            this.comment = null;
        }

        @SuppressWarnings("unused")
        public KnownString(String name, String value, String comment) {
            this.name = name;
            this.value = value;
            this.comment = comment;
        }
    }

    private static final List<KnownString> KNOWN_STRINGS;
    static {
        KNOWN_STRINGS = new ArrayList<>();
        try {
            ResourceFile resourceFile = Application.getModuleDataFile("Ghostrings", "known_strings.json");
            Reader reader = new InputStreamReader(resourceFile.getInputStream());
            Gson gson = new Gson();

            ArrayList<KnownString> jsonData = gson.fromJson(
                    reader,
                    new TypeToken<ArrayList<KnownString>>() {}.getType());

            KNOWN_STRINGS.addAll(jsonData.stream().
                    filter(ks -> ks != null).
                    sorted((ks1, ks2) -> Integer.valueOf(ks2.value.length()).compareTo(ks1.value.length())).
                    collect(Collectors.toList()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private final boolean verbose = false;
    private final String printfPrefix = getScriptName().replace("%", "%%") + "> ";

    /** Make printf log prefix consistent with println */
    @Override
    public void printf(String message, Object... args) {
        super.printf(printfPrefix + message, args);
    }

    private void printStringData(Data data) throws MemoryAccessException {
        final String strData = new String(data.getBytes(), StandardCharsets.UTF_8);
        printf("%s, %d:\t\"%s\"\n",
                data.getAddress(),
                data.getLength(),
                StringUtilities.convertControlCharsToEscapeSequences(strData));
    }

    private String escapedUtf8String(byte[] utf8bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : utf8bytes) {
            sb.append(String.format("\\x%02x", b));
        }
        return sb.toString();
    }

    /**
     * Find string data after a start address and define it. Clears any conflicting
     * data.
     * 
     * @throws MemoryAccessException
     */
    private Data findAndDefineString(AddressSet searchRange, String target) throws MemoryAccessException {
        // TODO: findBytes input string can contain regex, escape any regex characters
        byte[] utf8bytes = target.getBytes(StandardCharsets.UTF_8);
        int byteLen = utf8bytes.length;

        String escapedString = escapedUtf8String(utf8bytes);

        Address[] results = findBytes(searchRange, escapedString, 2, 1, false);
        if (results == null || results.length == 0) {
            if (verbose) {
                println("Target string not found");
            }
            return null;
        } else if (results.length > 1) {
            printf("More than one instance of target string \"%s\" found; skipping\n",
                    StringUtilities.convertControlCharsToEscapeSequences(target));
            return null;
        }

        Address result = results[0];

        Data conflict = getDataAt(result);
        if (conflict != null &&
                conflict.hasStringValue() &&
                Arrays.equals(utf8bytes, conflict.getBytes())) {
            // Already defined
            return null;
        }

        if (verbose) {
            printf("Found target string @ %s\n", result);
        }

        // Clear all conflicting data defined within the string
        /*
        Address endAddr = result.add(byteLen);
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
        */

        try {
            return createAsciiString(result, byteLen);
        } catch (CodeUnitInsertionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    @Override
    protected void run() throws Exception {
        if (KNOWN_STRINGS.isEmpty()) {
            println("Failed to load known string data");
            return;
        }

        GolangProgramInfo golangInfo = new GolangProgramInfo(this, true);

        Address strStart = golangInfo.getStringDataStart();
        Address strEnd = golangInfo.getStringDataEnd();
        AddressSet searchRange = new AddressSet(strStart, strEnd);

        printf("loaded %d strings\n", KNOWN_STRINGS.size());
        printf("searching %s to %s\n", strStart.toString(), strEnd.toString());

        monitor.setIndeterminate(false);
        monitor.setMaximum(KNOWN_STRINGS.size());
        monitor.setProgress(0);

        try {
            for (KnownString knownString : KNOWN_STRINGS) {
                monitor.setMessage(knownString.name);
                Data strData = findAndDefineString(searchRange, knownString.value);
                if (strData != null) {
                    println("Found and defined " + knownString.name);
                    printStringData(strData);
                }

                monitor.increment();
            }
        } catch (CancelledException e) {
            return;
        }
    }
}
