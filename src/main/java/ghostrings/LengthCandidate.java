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
package ghostrings;

import ghidra.program.model.pcode.PcodeOpAST;

public final class LengthCandidate {
    private int stringLength;
    private PcodeOpAST pcodeOp;
    private long stackOffset;

    public LengthCandidate(int stringLength, long stackOffset, PcodeOpAST pcodeOp) {
        this.setStringLength(stringLength);
        this.setStackOffset(stackOffset);
        this.setPcodeOp(pcodeOp);
    }

    public int getStringLength() {
        return stringLength;
    }

    public void setStringLength(int stringLength) {
        this.stringLength = stringLength;
    }

    public PcodeOpAST getPcodeOp() {
        return pcodeOp;
    }

    public void setPcodeOp(PcodeOpAST pcodeOp) {
        this.pcodeOp = pcodeOp;
    }

    public long getStackOffset() {
        return stackOffset;
    }

    public void setStackOffset(long stackOffset) {
        this.stackOffset = stackOffset;
    }
}