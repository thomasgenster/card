# -*- coding: UTF-8 -*-
"""
card: ISIM class
Copyright (C) 2024

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
"""

#################################
# ISIM class for IP Multimedia Services Identity Module
# Based on 3GPP TS 31.103
# 
# Provides authentication methods for IMS AKA
#################################

from card.ICC import UICC, ISO7816
from card.utils import *

# ISIM file identifiers under ADF.ISIM (as per TS 31.103)
EF_ISIM = {
    'IMPI':     0x6F02,  # IP Multimedia Private Identity
    'DOMAIN':   0x6F03,  # Home Network Domain Name
    'IMPU':     0x6F04,  # IP Multimedia Public Identity
    'AD':       0x6FAD,  # Administrative Data
    'ARR':      0x6F06,  # Access Rule Reference
    'IST':      0x6F07,  # ISIM Service Table
    'PCSCF':    0x6F09,  # P-CSCF Address
    'GBABP':    0x6FD5,  # GBA Bootstrapping parameters
    'GBANL':    0x6FD7,  # GBA NAF List
    'NAFKCA':   0x6FDD,  # NAF Key Centre Address
    'UICCIARI': 0x6FE7,  # UICC IARI
    'SMS':      0x6F3C,  # Short messages
    'SMSS':     0x6F43,  # SMS status
    'SMSR':     0x6F47,  # Short message status reports
    'SMSP':     0x6F42,  # Short message service parameters
    'PSISMSC':  0x6FE5,  # Public Service Identity of the SM-SC
}


class ISIM(UICC):
    """
    ISIM class inheriting from UICC
    
    Provides methods for IMS authentication using ISIM application
    Based on 3GPP TS 31.103 specification

    Usage:
        from card.ISIM import ISIM

        isim = ISIM()
        print("ISIM selected:", isim.ISIM_selected)

        # Authenticate
        RAND = [0xC0, 0x53, ...] # 16 bytes
        AUTN = [0xB5, 0x21, ...] # 16 bytes
        result = isim.authenticate(RAND, AUTN)
    """

    # ISIM AID prefix: 3GPP RID (A000000087) + ISIM PIX (1004)
    AID_ISIM_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]

    dbg = 0  # Set to 1 or 2 for debug output

    def __init__(self, reader=''):
        """
        Initialize ISIM card connection

        Selects ISIM application from the available AIDs on the card.
        After init, check self.ISIM_selected to verify ISIM was selected.
        """
        # Initialize parent ISO7816 class (like UICC does)
        ISO7816.__init__(self, CLA=0x00, reader=reader)
        self.AID = []
        self.AID_ISIM = None
        self.ISIM_selected = False

        if self.dbg >= 2:
            log(3, '(ISIM.__init__) type definition: %s' % type(self))
            log(3, '(ISIM.__init__) CLA definition: %s' % hex(self.CLA))

        # Try to select ISIM ADF
        self.ISIM_selected = self.SELECT_ADF_ISIM()

        if self.dbg:
            if self.ISIM_selected:
                log(3, '(ISIM.__init__) ISIM application selected successfully')
                log(3, '(ISIM.__init__) ISIM AID: %s' %
                    ' '.join(['%02X' % b for b in self.AID_ISIM]))
            else:
                log(1, '(ISIM.__init__) WARNING: ISIM application NOT selected')

    def SELECT_ADF_ISIM(self):
        """
        Select the ISIM AID (Application IDentifier)

        Returns True if ISIM AID exists and was selected, False otherwise
        """
        # First, scan for available AIDs in EF_DIR
        self._scan_AID()

        if self.dbg:
            log(3, '(SELECT_ADF_ISIM) Found %d AIDs on card' % len(self.AID))
            for i, aid in enumerate(self.AID):
                log(3, '  AID[%d]: %s' % (i, ' '.join(['%02X' % b for b in aid])))

        # Look for ISIM AID (starts with A0 00 00 00 87 10 04)
        for aid in self.AID:
            if len(aid) >= 7 and aid[:7] == self.AID_ISIM_prefix:
                self.AID_ISIM = aid
                if self.dbg:
                    log(3, '(SELECT_ADF_ISIM) Found ISIM AID')
                break

        if self.AID_ISIM is None:
            if self.dbg:
                log(1, '(SELECT_ADF_ISIM) No ISIM AID found on card')
            return False

        # Select the ISIM application by AID
        # P1=0x04 means "Select by DF name (AID)"
        # P2=0x04 means "Return FCP template"
        self.coms.push(self.SELECT_FILE(P1=0x04, P2=0x04, Data=self.AID_ISIM))

        sw = self.coms()[2]
        if self.dbg:
            log(3, '(SELECT_ADF_ISIM) SELECT response SW: %02X %02X' % (sw[0], sw[1]))

        if sw == (0x90, 0x00):
            return True
        elif sw[0] == 0x61:
            # More data available, get it
            self.coms.push(self.GET_RESPONSE(Le=sw[1]))
            if self.coms()[2] == (0x90, 0x00):
                return True

        if self.dbg:
            log(1, '(SELECT_ADF_ISIM) ISIM AID selection failed with SW: %02X %02X'
                % (sw[0], sw[1]))
        return False

    def _scan_AID(self):
        """
        Scan EF_DIR for available AIDs on the card
        """
        self.AID = []

        # Select MF first
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x00, Data=[0x3F, 0x00]))

        # Select EF_DIR (file 2F00 under MF)
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x00, Data=[0x2F, 0x00]))

        sw = self.coms()[2]
        if sw != (0x90, 0x00) and sw[0] != 0x61:
            if self.dbg:
                log(1, '(ISIM._scan_AID) Cannot select EF_DIR')
            return

        # Read records from EF_DIR
        rec_num = 1
        while rec_num < 20:  # Safety limit
            self.coms.push(self.READ_RECORD(rec_num, 0x04))

            sw = self.coms()[2]
            if sw == (0x90, 0x00) and len(self.coms()[3]) > 0:
                data = self.coms()[3]
                # Parse TLV structure for AID
                # Format: 61 L1 [4F L2 AID] [50 L3 label] ...
                if len(data) > 4 and data[0] == 0x61:
                    # Application template tag
                    i = 2  # Skip 61 and length
                    while i < len(data) - 1:
                        tag = data[i]
                        if i + 1 >= len(data):
                            break
                        length = data[i + 1]
                        if tag == 0x4F and i + 2 + length <= len(data):
                            # AID tag found
                            aid = list(data[i + 2:i + 2 + length])
                            self.AID.append(aid)
                            break
                        i += 2 + length
                rec_num += 1
            else:
                # No more records or error
                break

    def authenticate(self, RAND=[], AUTN=[], ctx='3G'):
        """
        Run IMS AKA authentication using AUTHENTICATE command

        self.authenticate(RAND, AUTN, ctx='3G') -> [RES, CK, IK] or [AUTS] or None

        Args:
            RAND: 16-byte random challenge (list of ints)
            AUTN: 16-byte authentication token (list of ints)
            ctx: '3G' for IMS AKA (default), 'GBA' for GBA bootstrapping

        Returns:
            On success: [RES, CK, IK] - list of 3 byte arrays
            On sync failure: [AUTS] - list with single AUTS byte array
            On error: None

        Note: ISIM application must be selected first (check self.ISIM_selected)

        Example:
            isim = ISIM()
            if not isim.ISIM_selected:
                print("ERROR: ISIM not selected")
            else:
                RAND = [0xC0, 0x53, 0x6F, 0xCF, 0x8F, 0x6D, 0xA7, 0x9F,
                        0xF7, 0x1C, 0x8E, 0xAF, 0x9C, 0x20, 0x49, 0x95]
                AUTN = [0xB5, 0x21, 0x69, 0xCA, 0xFE, 0xBB, 0x00, 0xFF,
                        0x12, 0x8F, 0xAF, 0x09, 0x46, 0xA6, 0xFA, 0xE1]
                result = isim.authenticate(RAND, AUTN)
        """
        # Check if ISIM is selected
        if not self.ISIM_selected:
            if self.dbg:
                log(1, '(authenticate) ERROR: ISIM application not selected')
            return None

        # Validate input parameters
        if len(RAND) != 16:
            if self.dbg:
                log(1, '(authenticate) ERROR: RAND must be 16 bytes, got %d' % len(RAND))
            return None

        if ctx in ('3G', 'GBA') and len(AUTN) != 16:
            if self.dbg:
                log(1, '(authenticate) ERROR: AUTN must be 16 bytes, got %d' % len(AUTN))
            return None

        # Build command data
        # Format: Length(RAND) | RAND | Length(AUTN) | AUTN
        # Total: 1 + 16 + 1 + 16 = 34 bytes

        if ctx == '3G':
            # IMS AKA / 3G security context
            # P2 = 0x81 means "UMTS/3G authentication context"
            P2 = 0x81
        elif ctx == 'GBA':
            # GBA bootstrapping context
            P2 = 0x84
        else:
            if self.dbg:
                log(1, '(authenticate) ERROR: unsupported context: %s' % ctx)
            return None

        # Build data: 0x10 | RAND[16] | 0x10 | AUTN[16]
        data = [len(RAND)] + list(RAND) + [len(AUTN)] + list(AUTN)

        if self.dbg:
            log(3, '(authenticate) Sending AUTHENTICATE with P2=%02X' % P2)
            log(3, '(authenticate) Data length: %d bytes' % len(data))

        # Send AUTHENTICATE command (INS = 0x88)
        self.coms.push(self.INTERNAL_AUTHENTICATE(P2=P2, Data=data))

        sw = self.coms()[2]

        if self.dbg:
            log(3, '(authenticate) Response SW: %02X %02X' % (sw[0], sw[1]))

        # Check response
        if sw[0] in (0x9F, 0x61):
            # Response data available, need to GET RESPONSE
            le = sw[1]
            self.coms.push(self.GET_RESPONSE(Le=le))

            if self.coms()[2] == (0x90, 0x00):
                resp_data = self.coms()[3]
                if self.dbg:
                    log(3, '(authenticate) Got %d bytes of response data' % len(resp_data))
                return self._parse_auth_response(resp_data, P2)

        elif sw == (0x90, 0x00):
            # Response data included directly
            resp_data = self.coms()[3]
            if len(resp_data) > 0:
                return self._parse_auth_response(resp_data, P2)

        # Handle specific error codes
        if sw[0] == 0x98:
            errors = {
                0x62: 'authentication error, no attempt left',
                0x64: 'authentication error, at least one attempt left',
                0x65: 'authentication error, no attempt left',
            }
            if self.dbg:
                msg = errors.get(sw[1], 'unknown authentication error')
                log(1, '(authenticate) %s' % msg)

        elif sw == (0x6D, 0x00):
            if self.dbg:
                log(1, '(authenticate) ERROR: Instruction not supported (6D00)')
                log(1, '(authenticate) This usually means ISIM is not selected')

        elif sw == (0x6E, 0x00):
            if self.dbg:
                log(1, '(authenticate) ERROR: Class not supported (6E00)')

        elif sw == (0x69, 0x82):
            if self.dbg:
                log(1, '(authenticate) ERROR: Security status not satisfied (6982)')
                log(1, '(authenticate) PIN verification may be required')

        else:
            if self.dbg:
                log(1, '(authenticate) ERROR: Unexpected SW %02X %02X' % (sw[0], sw[1]))

        return None

    def _parse_auth_response(self, data, P2):
        """
        Parse the AUTHENTICATE response data

        Returns:
            Success: [RES, CK, IK]
            Sync failure: [AUTS]
            Error: None
        """
        if len(data) < 1:
            return None

        tag = data[0]

        if self.dbg:
            log(3, '(_parse_auth_response) Response tag: %02X' % tag)
            log(3, '(_parse_auth_response) Full response: %s' %
                ' '.join(['%02X' % b for b in data]))

        # Tag 0xDB = successful 3G authentication
        # Response: DB L1 RES DC L2 CK DD L3 IK
        if tag == 0xDB:
            result = []
            idx = 1
            while idx < len(data):
                if idx >= len(data):
                    break
                length = data[idx]
                idx += 1
                if idx + length > len(data):
                    break
                value = list(data[idx:idx + length])
                result.append(value)
                idx += length

            if self.dbg:
                log(3, '(_parse_auth_response) Successful auth, got %d values' % len(result))
            return result if len(result) >= 1 else None

        # Tag 0xDC = synchronization failure, AUTS returned
        # Response: DC L AUTS
        elif tag == 0xDC:
            if len(data) >= 2:
                length = data[1]
                if len(data) >= 2 + length:
                    auts = list(data[2:2 + length])
                    if self.dbg:
                        log(3, '(_parse_auth_response) Sync failure, AUTS returned')
                    return [auts]
            return None

        # No tag - try LV parsing (some cards don't use tags)
        # Format: L1 RES L2 CK L3 IK
        else:
            if self.dbg:
                log(3, '(_parse_auth_response) No tag, trying LV parsing')

            result = []
            idx = 0
            while idx < len(data):
                length = data[idx]
                idx += 1
                if length == 0 or idx + length > len(data):
                    break
                value = list(data[idx:idx + length])
                result.append(value)
                idx += length

            return result if len(result) >= 1 else None

    def get_impi(self):
        """
        Read IMPI (IP Multimedia Private Identity) from EF_IMPI

        Returns the IMPI as a string, or None on error
        """
        if not self.ISIM_selected:
            return None

        # Select EF_IMPI (6F02)
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04,
                                        Data=[0x6F, 0x02]))

        sw = self.coms()[2]
        if sw != (0x90, 0x00) and sw[0] != 0x61:
            return None

        if sw[0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=sw[1]))

        # Read binary
        self.coms.push(self.READ_BINARY(0, 0))

        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # IMPI is TLV with tag 0x80
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                return bytes(data[2:2 + length]).decode('utf-8', errors='ignore')

        return None

    def get_impu(self, rec_num=1):
        """
        Read IMPU (IP Multimedia Public Identity) from EF_IMPU

        Args:
            rec_num: Record number (1-based)

        Returns the IMPU as a string, or None on error
        """
        if not self.ISIM_selected:
            return None

        # Select EF_IMPU (6F04)
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04,
                                        Data=[0x6F, 0x04]))

        sw = self.coms()[2]
        if sw != (0x90, 0x00) and sw[0] != 0x61:
            return None

        if sw[0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=sw[1]))

        # Read record
        self.coms.push(self.READ_RECORD(rec_num, 0x04))

        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # IMPU is TLV with tag 0x80
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                return bytes(data[2:2 + length]).decode('utf-8', errors='ignore')

        return None

    def get_domain(self):
        """
        Read Home Network Domain Name from EF_DOMAIN

        Returns the domain as a string, or None on error
        """
        if not self.ISIM_selected:
            return None

        # Select EF_DOMAIN (6F03)
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04,
                                        Data=[0x6F, 0x03]))

        sw = self.coms()[2]
        if sw != (0x90, 0x00) and sw[0] != 0x61:
            return None

        if sw[0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=sw[1]))

        # Read binary
        self.coms.push(self.READ_BINARY(0, 0))

        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # Domain is TLV with tag 0x80
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                return bytes(data[2:2 + length]).decode('utf-8', errors='ignore')

        return None