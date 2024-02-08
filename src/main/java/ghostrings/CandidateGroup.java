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
package ghostrings;

import java.util.List;

public final class CandidateGroup {
    private List<AddressCandidate> addresses;
    private List<LengthCandidate> lengths;

    public CandidateGroup(List<AddressCandidate> addrs, List<LengthCandidate> lens) {
        if (addrs == null || lens == null) {
            throw new IllegalArgumentException();
        }

        this.addresses = addrs;
        this.lengths = lens;
    }

    public List<AddressCandidate> getAddresses() {
        return addresses;
    }

    public List<LengthCandidate> getLengths() {
        return lengths;
    }
}
