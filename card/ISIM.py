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
    """
    
    # ISIM AID prefix: 3GPP RID (A000000087) + ISIM PIX (1004)
    AID_ISIM_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]
    
    def __init__(self, reader=''):
        """
        Initialize ISIM card connection
        
        Selects ISIM application from the available AIDs on the card
        """
        # Initialize parent UICC class
        ISO7816.__init__(self, CLA=0x00, reader=reader)
        self.AID = []
        self.AID_ISIM = None
        
        if self.dbg >= 2:
            log(3, '(ISIM.__init__) type definition: %s' % type(self))
            log(3, '(ISIM.__init__) CLA definition: %s' % hex(self.CLA))
        
        # Try to select ISIM ADF
        self.SELECT_ADF_ISIM()
    
    def SELECT_ADF_ISIM(self):
        """
        Select the ISIM AID (Application IDentifier)
        
        Returns True if ISIM AID exists and was selected, False otherwise
        """
        # First, scan for available AIDs in EF_DIR
        self._scan_AID()
        
        # Look for ISIM AID
        for aid in self.AID:
            if aid[:7] == self.AID_ISIM_prefix:
                self.AID_ISIM = aid
                break
        
        if self.AID_ISIM is None:
            if self.dbg:
                log(1, '(SELECT_ADF_ISIM) no ISIM AID found')
            return False
        
        # Select the ISIM application
        self.coms.push(self.SELECT_FILE(P1=0x04, P2=0x04, Data=self.AID_ISIM))
        
        if self.coms()[2] == (0x90, 0x00):
            if self.dbg >= 2:
                log(3, '(SELECT_ADF_ISIM) ISIM AID selected successfully')
            return True
        elif self.coms()[2][0] == 0x61:
            # Get response for additional data
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
            if self.coms()[2] == (0x90, 0x00):
                return True
        
        if self.dbg:
            log(1, '(SELECT_ADF_ISIM) ISIM AID selection failed: %s' 
                % self.coms()[2])
        return False
    
    def _scan_AID(self):
        """
        Scan EF_DIR for available AIDs
        """
        self.AID = []
        
        # Select MF first
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x00, Data=[0x3F, 0x00]))
        
        # Select EF_DIR
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x00, Data=[0x2F, 0x00]))
        
        if self.coms()[2] != (0x90, 0x00) and self.coms()[2][0] != 0x61:
            return
        
        # Read records from EF_DIR
        rec_num = 1
        while True:
            self.coms.push(self.READ_RECORD(rec_num, 0x04))
            
            if self.coms()[2] == (0x90, 0x00) and len(self.coms()[3]) > 0:
                data = self.coms()[3]
                # Parse TLV structure for AID (tag 0x61 contains application template)
                if len(data) > 2 and data[0] == 0x61:
                    # Look for AID tag (0x4F)
                    i = 2  # Skip template tag and length
                    while i < len(data) - 1:
                        tag = data[i]
                        length = data[i + 1]
                        if tag == 0x4F and i + 2 + length <= len(data):
                            aid = data[i + 2:i + 2 + length]
                            self.AID.append(aid)
                            break
                        i += 2 + length
                rec_num += 1
            else:
                break
    
    def get_impi(self):
        """
        Read IMPI (IP Multimedia Private Identity) from EF_IMPI
        
        Returns the IMPI as a string, or None on error
        """
        # Select EF_IMPI
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04, 
                                        Data=[0x6F, 0x02]))
        
        if self.coms()[2] != (0x90, 0x00) and self.coms()[2][0] != 0x61:
            if self.dbg:
                log(1, '(get_impi) cannot select EF_IMPI')
            return None
        
        # Handle response data if present
        if self.coms()[2][0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
        
        # Read binary content
        self.coms.push(self.READ_BINARY(0, 0))
        
        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # IMPI is stored as NAI TLV (tag 0x80)
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                impi_bytes = data[2:2 + length]
                return ''.join([chr(b) for b in impi_bytes])
        
        return None
    
    def get_impu(self, rec_num=1):
        """
        Read IMPU (IP Multimedia Public Identity) from EF_IMPU
        
        Args:
            rec_num: Record number (1-based) to read
            
        Returns the IMPU as a string, or None on error
        """
        # Select EF_IMPU
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04,
                                        Data=[0x6F, 0x04]))
        
        if self.coms()[2] != (0x90, 0x00) and self.coms()[2][0] != 0x61:
            if self.dbg:
                log(1, '(get_impu) cannot select EF_IMPU')
            return None
        
        # Handle response data
        if self.coms()[2][0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
        
        # Read record
        self.coms.push(self.READ_RECORD(rec_num, 0x04))
        
        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # IMPU is stored as URI TLV (tag 0x80)
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                impu_bytes = data[2:2 + length]
                return ''.join([chr(b) for b in impu_bytes])
        
        return None
    
    def get_domain(self):
        """
        Read Home Network Domain Name from EF_DOMAIN
        
        Returns the domain name as a string, or None on error
        """
        # Select EF_DOMAIN
        self.coms.push(self.SELECT_FILE(P1=0x00, P2=0x04,
                                        Data=[0x6F, 0x03]))
        
        if self.coms()[2] != (0x90, 0x00) and self.coms()[2][0] != 0x61:
            if self.dbg:
                log(1, '(get_domain) cannot select EF_DOMAIN')
            return None
        
        # Handle response data
        if self.coms()[2][0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
        
        # Read binary content
        self.coms.push(self.READ_BINARY(0, 0))
        
        if self.coms()[2] == (0x90, 0x00):
            data = self.coms()[3]
            # Domain is stored as TLV (tag 0x80)
            if len(data) > 2 and data[0] == 0x80:
                length = data[1]
                domain_bytes = data[2:2 + length]
                return ''.join([chr(b) for b in domain_bytes])
        
        return None
    
    def authenticate(self, RAND=[], AUTN=[], ctx='3G'):
        """
        Run IMS AKA authentication using AUTHENTICATE command
        
        self.authenticate(RAND, AUTN, ctx='3G') -> [key1, key2...],
        LV parsing style
        
        Runs the INTERNAL AUTHENTICATE command in the ISIM
        with the right context:
            ctx = '3G', 'GBA' ('HTTP-DIGEST' not recommended for 3GPP)
            RAND and AUTN are list of bytes
            
        Returns a list containing the keys (list of bytes) computed 
        in the ISIM, on success:
            [RES, CK, IK] or [AUTS] for '3G' / IMS AKA
            [RES] or [AUTS] for 'GBA'
        or None on error
        
        Based on 3GPP TS 31.103 section 7.1 (AUTHENTICATE function)
        """
        # Validate input parameters
        if ctx in ('3G', 'GBA') and len(RAND) != 16:
            if self.dbg:
                log(1, '(authenticate) bad RAND parameter (must be 16 bytes): aborting')
            return None
        
        if ctx == '3G' and len(AUTN) != 16:
            if self.dbg:
                log(1, '(authenticate) bad AUTN parameter (must be 16 bytes): aborting')
            return None
        
        # Build input data and set P2 based on context
        inp = []
        
        if ctx == '3G':
            # IMS AKA context (same as USIM 3G context)
            P2 = 0x81
            inp = [0xDD]  # Tag for 3G security context
            inp.extend([len(RAND)] + RAND + [len(AUTN)] + AUTN)
            
        elif ctx == 'GBA':
            # GBA bootstrapping context
            P2 = 0x84
            inp = [0xDD]  # Tag for GBA security context
            inp.extend([len(RAND)] + RAND + [len(AUTN)] + AUTN)
            
        else:
            if self.dbg:
                log(1, '(authenticate) unsupported context %s: aborting' % ctx)
            return None
        
        # Send AUTHENTICATE command (INS = 0x88)
        self.coms.push(self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp))
        
        # Process response
        if self.coms()[2][0] in (0x9F, 0x61):
            # Response data available, get it
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
            
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                return self._parse_auth_response(val, ctx)
        
        elif self.coms()[2] == (0x90, 0x00):
            # Response data already in response
            if len(self.coms()[3]) > 0:
                return self._parse_auth_response(self.coms()[3], ctx)
        
        # Check for specific error codes
        sw1, sw2 = self.coms()[2]
        
        if sw1 == 0x98:
            if sw2 == 0x62:
                if self.dbg:
                    log(1, '(authenticate) authentication error, no attempt left')
            elif sw2 == 0x64:
                if self.dbg:
                    log(1, '(authenticate) authentication error, '
                        'verification failed, more attempts')
            elif sw2 == 0x65:
                if self.dbg:
                    log(1, '(authenticate) authentication error, '
                        'verification failed, no more attempts')
        
        if self.dbg:
            log(1, '(authenticate) failed with SW: %02X%02X' % (sw1, sw2))
        
        return None
    
    def _parse_auth_response(self, val, ctx):
        """
        Parse the AUTHENTICATE response data
        
        Returns list of key values extracted from response
        """
        if len(val) < 1:
            return None
        
        result = []
        
        # Check response tag
        tag = val[0]
        
        if tag == 0xDB:
            # Successful authentication (3G/IMS AKA)
            # Format: DB L1 [RES] DC L2 [CK] DD L3 [IK]
            idx = 1
            
            while idx < len(val) - 1:
                t = val[idx]
                l = val[idx + 1]
                
                if idx + 2 + l > len(val):
                    break
                
                v = val[idx + 2:idx + 2 + l]
                result.append(v)
                idx += 2 + l
            
            return result if result else None
        
        elif tag == 0xDC:
            # Synchronisation failure - AUTS returned
            # Format: DC L [AUTS]
            if len(val) > 2:
                l = val[1]
                auts = val[2:2 + l]
                return [auts]
            return None
        
        elif tag == 0xDE:
            # GBA response
            idx = 1
            while idx < len(val) - 1:
                t = val[idx]
                l = val[idx + 1]
                if idx + 2 + l > len(val):
                    break
                v = val[idx + 2:idx + 2 + l]
                result.append(v)
                idx += 2 + l
            return result if result else None
        
        # Unknown tag, try parsing as LV structure
        idx = 0
        while idx < len(val):
            if idx >= len(val):
                break
            l = val[idx]
            if l == 0 or idx + 1 + l > len(val):
                break
            v = val[idx + 1:idx + 1 + l]
            result.append(v)
            idx += 1 + l
        
        return result if result else None
    
    def GBA_derivation(self, NAF_ID=[], IMPI=[]):
        """
        Run GBA key derivation using AUTHENTICATE command
        
        self.GBA_derivation(NAF_ID, IMPI) -> [Ks_ext_naf]
        
        Runs the INTERNAL AUTHENTICATE command in the ISIM
        with the GBA derivation context:
            NAF_ID is a list of bytes:
                "NAF domain name"||"security protocol id"
            IMPI is a list of bytes:
                The ISIM's IMPI
                
        Returns a list with GBA ext key (list of bytes) computed 
        in the ISIM:
            [Ks_ext_naf]
        or None on error
        
        See TS 33.220 for GBA specific formats
        """
        if len(NAF_ID) == 0:
            if self.dbg:
                log(1, '(GBA_derivation) empty NAF_ID: aborting')
            return None
        
        # Build input data for GBA derivation (P2 = 0x85)
        P2 = 0x85
        inp = [0xDE]  # Tag for GBA NAF derivation
        inp.extend([len(NAF_ID)] + NAF_ID)
        inp.extend([len(IMPI)] + IMPI)
        
        # Send AUTHENTICATE command
        self.coms.push(self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp))
        
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
            
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                # Parse response for Ks_ext_naf
                if len(val) > 2:
                    result = []
                    idx = 0
                    while idx < len(val) - 1:
                        l = val[idx]
                        if l == 0 or idx + 1 + l > len(val):
                            break
                        v = val[idx + 1:idx + 1 + l]
                        result.append(v)
                        idx += 1 + l
                    return result if result else None
        
        if self.dbg:
            log(1, '(GBA_derivation) failed with SW: %02X%02X' 
                % self.coms()[2])
        return None


# Helper function to create ISIM instance
def ISIM_card(reader=''):
    """
    Create and return an ISIM card instance
    
    Args:
        reader: Optional reader name/index
        
    Returns:
        ISIM instance, or None if ISIM application not found
    """
    try:
        isim = ISIM(reader=reader)
        if isim.AID_ISIM:
            return isim
        else:
            isim.disconnect()
            return None
    except Exception as e:
        log(1, '(ISIM_card) error: %s' % str(e))
        return None