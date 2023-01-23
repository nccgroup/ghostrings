# Ghostrings

Scripts for recovering string definitions in Go binaries with P-Code analysis.
Tested with x86, x86-64, ARM, and ARM64.

There are two main parts to the string recovery flow with Ghostrings:

* Find dynamic string structure definitions on the stack via P-Code analysis, then use their start address and length values to define strings in the `go.string.*` string data blob
* Fill the remaining gaps in `go.string.*` using some mathematical checks, based on the ascending length order of the strings

These two techniques greatly simplify recovering all string definitions in the `go.string.*` blob with minimal manual intervention.

### Background

A well-known issue with reverse engineering Go programs is that the lack of null terminators in Go strings makes recovering string definitions from compiled binaries difficult. Many of a Go program's constant string values are stored together in one giant blob in the compiled build, without any terminator characters built into the string data to mark where one string ends and another begins. Even a simple program that just prints "Hello world!" has over 1,500 strings in it related to the Go runtime system and other standard libraries. This can cause typical ASCII string discovery implementations, such as the one provided by Ghidra, to create false positive string definitions that are tens of thousands of characters long.

Instead of null terminated strings, Go uses a string structure that consists of a pointer and length value. Many of these string structures are created on the program’s stack at runtime, so recovering individual string start locations and length values requires analyzing the compiled machine code. There are a few existing scripts that perform this analysis by checking for certain patterns of x86-64 instructions, but they miss structures created with unhandled variations of instructions that ultimately have the same effect on the stack, and they're also restricted to a specific ISA.

Ghostrings avoids both these problems by working with the simplified, architecture independent P-Code operations produced by Ghidra’s decompiler analysis.

## Setup

### Installing

In Ghidra:

1. File -> Install Extensions -> Add extension
2. Select the extension ZIP file

### Development

For Eclipse with GhidraDev plugin:

1. Clone repo
2. File -> Import -> Projects from Folder or Archive
3. Select repo directory
4. GhidraDev -> Link Ghidra...
5. Select imported project

### Building

Build with Eclipse:

* GhidraDev -> Export -> Ghidra Module Extension...

Build directly with Gradle:

```console
$ cd Ghostrings
$ gradle -PGHIDRA_INSTALL_DIR=<ghidra_install_dir>
```

## Scripts

### Golang

These can be found in the Golang category in the Script Manager.

* `GoDynamicStrings.java`
  * Analyzes P-Code to find string structures created on the stack. Uses the lower level "register" style analysis.
* `GoDynamicStringsSingle.java`
  * Performs the same analysis as `GoDynamicStrings.java`, but uses a single decompiler process. Use this if analyzing a large binary causes the parallel decompiler processes to exhaust system memory.
* `GoDynamicStringsHigh.java`
  * Experimental, uses P-Code output from the higher level "normalize" style analysis. Currently depends on a hack that turns off deadcode elimination in the decompiler (see <https://research.nccgroup.com/2022/05/20/earlyremoval-in-the-conservatory-with-the-wrench/>). *This hack breaks in Ghidra 10.2.*
* `GoStaticStrings.java`
  * Find Go string structures statically allocated in read-only memory.
* `GoKnownStrings.java`
  * Searches for standard unique strings and defines them. String data is loaded from `data/known_strings.json`.
* `GoStringFiller.java`
  * Fills in gaps in `go.string.*` after initial analysis, based on strings being ordered by ascending length.

### P-Code

This can be found in the PCode category in the Script Manager.

* `PrintHighPCode.java`
  * Prints high P-Code output for the currently selected function to the console, with a selector for the decompiler simplification style to use.


## String recovery flow

Here’s the general flow for using these scripts to recover string definitions in a Go binary:

1. To eliminate incorrect string definitions, clear all automatically defined strings in the read-only data memory block (`.rodata`, `.rdata`, or `__rodata`).
   1. In the "Defined Strings" window, add the "Mem Block" column to the display
   2. Create a filter on the memory block column to only show strings in the target block
   3. Select all strings in the window, then in the listing right-click and choose "Clear Code Bytes"
2. *(Optional)* Run `GoKnownStrings.java` to detect some standard strings.
3. Run `GoStaticStrings.java`.
4. Run `GoDynamicStrings.java`.
5. Run `GoStringFiller.java`.
   * If it detects false positive short strings (strings that violate the ascending length order), clear them and re-run the script. There is an option to do this automatically.
   * If the binary is stripped, locate the area of one byte strings found by the dynamic strings script.
     Ensure it's the start of the grouped together non-null-terminated strings (more strings should be defined after with length in ascending order).
     Create the label `go.string.*` at the first one byte string.
6. Check for remaining gaps in `go.string.*`, and define any strings with obvious start and end points. Sometimes defining one or two strings and re-running `GoStringFiller.java` is sufficient to fill in remaining gaps.
7. *(Optional)* Re-run Ghidra's built-in ASCII String analysis tool.
   * Disable overwriting existing strings. Run with and then without the null terminator requirement.


## Release Info

Copyright 2022 NCC Group. Released under the GPLv3 license (see LICENSE).

Main project author: James Chambers <james.chambers@nccgroup.com>
