# -*- coding: UTF-8 -*-
"""
card: USIM class
Copyright (C) 2013 benoit.michau@cartes-a-puce.org

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

#################################
# USIM class
# for ETSI / 3GPP USIM card
# see 3GPP TS 31.102
#################################

from card.ICC import UICC, ISO7816
from card.utils import *


# GSM 7-bit default alphabet (3GPP TS 23.038) for SPN decoding
GSM7_BASIC = (
    '@£$¥èéùìòÇ\nØø\rÅå'
    'Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ'
    ' !"#¤%&\'()*+,-./'
    '0123456789:;<=>?'
    '¡ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZÄÖÑÜ§'
    '¿abcdefghijklmno'
    'pqrstuvwxyzäöñüà'
)


class USIM(UICC):
    """
    defines attributes, methods and facilities for ETSI / 3GPP USIM card
    check USIM specifications in 3GPP TS 31.102

    inherits (eventually overrides) methods and objects from UICC class
    use self.dbg = 1 or more to print live debugging information
    """

    def __init__(self, reader=''):
        """
        initializes like an ISO7816-4 card with CLA=0x00
        and checks available AID (Application ID) read from EF_DIR

        initializes on the MF
        """
        # initialize like a UICC
        ISO7816.__init__(self, CLA=0x00, reader=reader)
        self.AID        = []
        self.AID_GP     = {}
        self.AID_USIM   = None
        self.AID_ISIM   = None
        #
        if self.dbg >= 2:
            log(3, '(UICC.__init__) type definition: %s' % type(self))
            log(3, '(UICC.__init__) CLA definition: %s' % hex(self.CLA))
        #
        self.SELECT_ADF_USIM()

    def SELECT_ADF_USIM(self):
        """
        selects the USIM AID

        returns True if the USIM AID exists, False otherwise
        may print an error in case the USIM AID selection fails
        """
        # USIM selection from AID
        # get available AID on the card
        self.get_AID()
        #
        USIM_AID_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]
        ISIM_AID_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]
        #
        for aid in self.AID:
            if aid[:7] == USIM_AID_prefix:
                self.AID_USIM = aid
            elif aid[:7] == ISIM_AID_prefix:
                self.AID_ISIM = aid
        #
        if self.AID_USIM is None:
            if self.dbg:
                log(1, '(SELECT_ADF_USIM) no USIM AID found')
            return False
        #
        # select USIM by AID
        self.coms.push(self.SELECT_FILE(P1=0x04, P2=0x04, Data=self.AID_USIM))
        #
        if self.coms()[2] == (0x90, 0x00):
            if self.dbg >= 2:
                log(3, '(USIM.SELECT_ADF_USIM) USIM AID selection succeeded\n')
            return True
        elif self.coms()[2][0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
            if self.coms()[2] == (0x90, 0x00):
                if self.dbg >= 2:
                    log(3, '(USIM.SELECT_ADF_USIM) USIM AID selection succeeded\n')
                return True
        #
        if self.dbg:
            log(1, '(SELECT_ADF_USIM) USIM AID selection failed')
        return False

    def SELECT_ADF_ISIM(self):
        """
        selects the ISIM AID

        returns True if the ISIM AID exists, False otherwise
        may print an error in case the ISIM AID selection fails
        """
        # ISIM selection from AID
        if self.AID_ISIM is None:
            # try to get AIDs if not already done
            if not self.AID:
                self.get_AID()
            ISIM_AID_prefix = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]
            for aid in self.AID:
                if aid[:7] == ISIM_AID_prefix:
                    self.AID_ISIM = aid
                    break
        #
        if self.AID_ISIM is None:
            if self.dbg:
                log(1, '(SELECT_ADF_ISIM) no ISIM AID found')
            return False
        #
        # select ISIM by AID
        self.coms.push(self.SELECT_FILE(P1=0x04, P2=0x04, Data=self.AID_ISIM))
        #
        if self.coms()[2] == (0x90, 0x00):
            if self.dbg >= 2:
                log(3, '(USIM.SELECT_ADF_ISIM) ISIM AID selection succeeded\n')
            return True
        elif self.coms()[2][0] == 0x61:
            self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
            if self.coms()[2] == (0x90, 0x00):
                if self.dbg >= 2:
                    log(3, '(USIM.SELECT_ADF_ISIM) ISIM AID selection succeeded\n')
                return True
        #
        if self.dbg:
            log(1, '(SELECT_ADF_ISIM) ISIM AID selection failed')
        return False

    def get_imsi(self):
        """
        get_imsi() -> string(IMSI)

        reads IMSI value at address [0x6F, 0x07]
        returns IMSI string on success or None on error
        """
        # select IMSI file
        imsi = self.select([0x6F, 0x07])
        if imsi is None:
            return None
        # and parse the received data into the IMSI structure
        if 'Data' in imsi.keys() and len(imsi['Data']) == 9:
            return decode_BCD(imsi['Data'])[3:]

        # if issue with the content of the DF_IMSI file
        if self.dbg:
            log(1, '(get_imsi) %s' % self.coms())
        return None

    def get_CS_keys(self):
        """
        get_CS_keys() -> [KSI, CK, IK]

        reads CS UMTS keys at address [0x6F, 0x08]
        returns list of 3 keys, each are list of bytes, on success
        or None on error
        """
        EF = self.select([0x6F, 0x08])
        if EF is None:
            return None
        if 'Data' in EF.keys() and len(EF['Data']) >= 33:
            return [EF['Data'][0:1], EF['Data'][1:17], EF['Data'][17:33]]
        return None

    def get_PS_keys(self):
        """
        get_PS_keys() -> [KSI, CK, IK]

        reads PS UMTS keys at address [0x6F, 0x09]
        returns list of 3 keys, each are list of bytes, on success
        or None on error
        """
        EF = self.select([0x6F, 0x09])
        if EF is None:
            return None
        if 'Data' in EF.keys() and len(EF['Data']) >= 33:
            return [EF['Data'][0:1], EF['Data'][1:17], EF['Data'][17:33]]
        return None

    def get_GBA_BP(self):
        """
        get_GBA_BP() -> [[RAND], [B-TID], [KeyLifetime]]

        reads GBA bootstrapping parameters at address [0x6F, 0xD6]
        returns list of 3 items, each are list of bytes
        or None on error
        """
        EF = self.select([0x6F, 0xD6])
        if EF is None:
            return None
        if 'Data' in EF.keys() and len(EF['Data']) >= 39:
            rand = EF['Data'][1:17]
            btid_len = EF['Data'][17]
            btid = EF['Data'][18:18+btid_len]
            life = EF['Data'][18+btid_len:18+btid_len+4]
            return [rand, btid, life]
        return None

    def authenticate(self, RAND=[], AUTN=[], ctx='3G'):
        """
        self.authenticate(RAND, AUTN, ctx='3G') -> [key1, key2...],
        LV parsing style

        runs the INTERNAL AUTHENTICATE command in the USIM
        with the right context:
            ctx = '2G', '3G', 'GBA' ('MBMS' or other not supported at this time)
            RAND and AUTN are list of bytes; for '2G' context, AUTN is not used
        returns a list containing the keys (list of bytes) computed in the USIM,
        on success:
            [RES, CK, IK (, Kc)] or [AUTS] for '3G'
            [RES] or [AUTS] for 'GBA'
            [RES, Kc] for '2G'
        or None on error
        """
        # prepare input data for authentication

        if ctx in ('3G', 'VGCS', 'GBA', 'MBMS') and len(RAND) != 16 \
        and len(AUTN) != 16:
            if self.dbg:
                log(1, '(authenticate) bad AUTN parameter: aborting')
            return None

        #
        inp = []
        if ctx == '3G':
            P2 = 0x81

        elif ctx == 'VGCS':
            P2 = 0x82
            if self.dbg:
                log(1, '(authenticate) VGCS auth not implemented: aborting')
            return None

        elif ctx == 'MBMS':
            P2 = 0x83
            if self.dbg:
                log(1, '(authenticate) MBMS auth not implemented: aborting')
            return None

        elif ctx == 'GBA':
            P2 = 0x84
            inp = [0xDD]
        inp.extend( [len(RAND)] + RAND + [len(AUTN)] + AUTN )
        if ctx not in ['3G', 'VGCS', 'MBMS', 'GBA']:
        # and also, if ctx == '2G'... the safe way
        # to avoid desynchronizing our USIM counter
            P2 = 0x80
            if len(RAND) != 16:
                if self.dbg:
                    log(1, '(authenticate) bad RAND parameter: aborting')
                return None
            # override input value for 2G authent
            inp = [len(RAND)] + RAND

        self.coms.push( self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp) )
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push( self.GET_RESPONSE(Le=self.coms()[2][1]) )
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                if P2 == 0x80:
            # 2G context: RES, Kc
                    if val[0] == 0x04:
                        return [val[1:1+val[0]], val[1+val[0]+1:]]
            # 3G, GBA, VGCS context: RES, CK, IK (, Kc)
                elif val[0] == 0xDB:
                    ret, index = [], 1
                    while index < len(val):
                        l = val[index]
                        ret.append( val[index+1:index+1+l] )
                        index += 1+l
                    return ret
            # sync failure: AUTS
                elif val[0] == 0xDC:
                    return [ val[2:] ]
        # invalid response
        return None

    def GBA_derivation(self, NAF_ID=[], IMPI=[]):
        """
        self.GBA_derivation(NAF_ID, IMPI) -> [Ks_ext_naf]

        runs the INTERNAL AUTHENTICATE command in the USIM
        with the GBA derivation context:
            NAF_ID is a list of bytes (use stringToByte())
                "NAF domain name"||"security protocol id",
                eg: "application.org"||"0x010001000a" (> TLS with RSA and SHA)
            IMPI is a list of bytes
                "IMSI@ims.mncXXX.mccYYY.3gppnetwork.org" if no IMS IMPI
                is specifically defined in the USIM
        returns a list with GBA ext key (list of bytes) computed in the USIM:
            [Ks_ext_naf]
            Ks_int_naf remains available in the USIM
            for further GBA_U key derivation
        or None on error

        see TS 33.220 for GBA specific formats
        """
        if len(NAF_ID) > 255 or len(IMPI) > 255:
            if self.dbg:
                log(1, '(GBA_derivation) bad parameters: aborting')
            return None
        #
        P2 = 0x85
        inp = [0xDE, len(NAF_ID)] + NAF_ID + [len(IMPI)] + IMPI

        self.coms.push( self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp) )
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push( self.GET_RESPONSE(Le=self.coms()[2][1]) )
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                if val[0] == 0xDB:
                    return [ val[2:2+val[1]] ]
        # invalid response
        return None

    ###########################################
    # SPN (Service Provider Name) functions
    ###########################################

    def _decode_gsm7(self, data):
        """
        Decode GSM 7-bit encoded bytes to string.

        Args:
            data: List of bytes (each byte has bit 8 = 0 for GSM7)

        Returns:
            Decoded string
        """
        result = []
        for b in data:
            if b == 0xFF:
                # Padding/unused byte
                break
            if b < 128 and b < len(GSM7_BASIC):
                result.append(GSM7_BASIC[b])
            else:
                # Invalid or extended character
                result.append('?')
        return ''.join(result)

    def _decode_ucs2(self, data):
        """
        Decode UCS2 encoded bytes to string.

        Handles three UCS2 coding schemes per 3GPP TS 31.102 Annex A:
        - 0x80: Simple UCS2 (big-endian 16-bit chars)
        - 0x81: UCS2 with half-page base pointer
        - 0x82: UCS2 with full base pointer

        Args:
            data: List of bytes starting with 0x80, 0x81, or 0x82

        Returns:
            Decoded string
        """
        if not data:
            return ''

        scheme = data[0]

        if scheme == 0x80:
            # Simple UCS2: pairs of bytes (big-endian)
            result = []
            i = 1
            while i + 1 < len(data):
                if data[i] == 0xFF and data[i + 1] == 0xFF:
                    break
                code = (data[i] << 8) | data[i + 1]
                if code != 0xFFFF:
                    result.append(chr(code))
                i += 2
            return ''.join(result)

        elif scheme == 0x81:
            # UCS2 with half-page base
            if len(data) < 3:
                return ''
            num_chars = data[1]
            base = data[2] << 7  # Base pointer (half-page)
            result = []
            for i in range(3, min(3 + num_chars, len(data))):
                b = data[i]
                if b == 0xFF:
                    break
                if b & 0x80:
                    # UCS2 character from base page
                    result.append(chr(base + (b & 0x7F)))
                else:
                    # GSM 7-bit character
                    if b < len(GSM7_BASIC):
                        result.append(GSM7_BASIC[b])
            return ''.join(result)

        elif scheme == 0x82:
            # UCS2 with full base pointer
            if len(data) < 4:
                return ''
            num_chars = data[1]
            base = (data[2] << 8) | data[3]  # Full 16-bit base
            result = []
            for i in range(4, min(4 + num_chars, len(data))):
                b = data[i]
                if b == 0xFF:
                    break
                if b & 0x80:
                    # UCS2 character from base
                    result.append(chr(base + (b & 0x7F)))
                else:
                    # GSM 7-bit character
                    if b < len(GSM7_BASIC):
                        result.append(GSM7_BASIC[b])
            return ''.join(result)

        else:
            # Unknown scheme, try as raw bytes
            return bytes(data).decode('utf-8', errors='ignore')

    def _decode_spn_string(self, data):
        """
        Decode SPN string from raw bytes.

        Automatically detects encoding (GSM7 or UCS2).

        Args:
            data: List of bytes (the SPN field, bytes 2-17 of EF_SPN)

        Returns:
            Decoded string
        """
        if not data:
            return ''

        # Check for UCS2 encoding markers
        if data[0] in (0x80, 0x81, 0x82):
            return self._decode_ucs2(data)

        # Otherwise assume GSM 7-bit
        return self._decode_gsm7(data)

    def get_gid1(self):
        """
        get_gid1() -> string

        Reads the Group Identifier Level 1 (GID1) from EF_GID1 (0x6F3E)

        The GID1 is used to identify a group of SIMs for a particular
        application. It's typically used for SIM-lock purposes.

        Returns:
            GID1 as hex string on success, or None on error

        Example:
            u = USIM()
            print("GID1:", u.get_gid1())
        """
        # Select EF_GID1
        EF = self.select([0x6F, 0x3E])
        if EF is None:
            return None

        if 'Data' not in EF.keys() or len(EF['Data']) < 1:
            return None

        data = EF['Data']

        # GID1 contains identifier bytes, 0xFF indicates unused bytes
        # Filter out padding bytes and convert to hex string
        gid1_bytes = []
        for b in data:
            if b == 0xFF:
                break
            gid1_bytes.append(b)

        if not gid1_bytes:
            return ''

        # Return as hex string (common format for GID1)
        return ''.join('%02X' % b for b in gid1_bytes)

    def get_spn(self):
        """
        get_spn() -> string

        Reads the Service Provider Name (SPN) from EF_SPN (0x6F46)

        Returns:
            SPN string on success, or None on error

        Example:
            u = USIM()
            print("Service Provider:", u.get_spn())
        """
        # Select EF_SPN
        EF = self.select([0x6F, 0x46])
        if EF is None:
            return None

        if 'Data' not in EF.keys() or len(EF['Data']) < 2:
            return None

        data = EF['Data']

        # EF_SPN structure:
        # Byte 1: Display condition
        # Bytes 2-17: Service Provider Name (16 bytes)
        spn_bytes = list(data[1:17]) if len(data) >= 17 else list(data[1:])

        # Decode and strip trailing whitespace
        spn_string = self._decode_spn_string(spn_bytes)
        return spn_string.rstrip() if spn_string else None

    def get_spn_detail(self):
        """
        get_spn_detail() -> dict

        Reads Service Provider Name with full details from EF_SPN (0x6F46)

        Returns:
            Dictionary with:
                'spn': The service provider name string
                'display_condition': Raw display condition byte
                'display_plmn_required': Boolean (bit 1 of display condition)
                'raw': Raw bytes of EF_SPN
            Or None on error

        Example:
            u = USIM()
            info = u.get_spn_detail()
            if info:
                print("SPN:", info['spn'])
                print("Display PLMN required:", info['display_plmn_required'])
        """
        # Select EF_SPN
        EF = self.select([0x6F, 0x46])
        if EF is None:
            return None

        if 'Data' not in EF.keys() or len(EF['Data']) < 2:
            return None

        data = EF['Data']

        # Parse EF_SPN structure
        display_condition = data[0]
        spn_bytes = list(data[1:17]) if len(data) >= 17 else list(data[1:])

        # Decode the SPN string
        spn_string = self._decode_spn_string(spn_bytes)
        spn_string = spn_string.rstrip() if spn_string else ''

        return {
            'spn': spn_string,
            'display_condition': display_condition,
            'display_plmn_required': bool(display_condition & 0x01),
            'raw': list(data)
        }

    ###############################################
    # ISIM Authentication (when ISIM is selected)
    ###############################################

    def authenticate_isim(self, RAND=[], AUTN=[]):
        """
        self.authenticate_isim(RAND, AUTN) -> [RES, CK, IK] or [AUTS] or None

        Runs IMS AKA authentication on ISIM application.

        IMPORTANT: Call SELECT_ADF_ISIM() first to select the ISIM application!

        Args:
            RAND: 16-byte random challenge (list of ints)
            AUTN: 16-byte authentication token (list of ints)

        Returns:
            On success: [RES, CK, IK] - list of 3 byte arrays
            On sync failure: [AUTS] - list with single AUTS byte array
            On error: None

        Example:
            u = USIM()
            if u.SELECT_ADF_ISIM():
                RAND = [0xC0, 0x53, ...] # 16 bytes
                AUTN = [0xB5, 0x21, ...] # 16 bytes
                result = u.authenticate_isim(RAND, AUTN)
        """
        # Validate parameters
        if len(RAND) != 16:
            if self.dbg:
                log(1, '(authenticate_isim) RAND must be 16 bytes')
            return None

        if len(AUTN) != 16:
            if self.dbg:
                log(1, '(authenticate_isim) AUTN must be 16 bytes')
            return None

        # P2 = 0x81 for UMTS/3G/IMS AKA context
        P2 = 0x81

        # Build data: 0x10 | RAND[16] | 0x10 | AUTN[16]
        data = [len(RAND)] + list(RAND) + [len(AUTN)] + list(AUTN)

        # Send AUTHENTICATE command
        self.coms.push(self.INTERNAL_AUTHENTICATE(P2=P2, Data=data))

        sw = self.coms()[2]

        # Handle response
        if sw[0] in (0x9F, 0x61):
            self.coms.push(self.GET_RESPONSE(Le=sw[1]))

            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                return self._parse_auth_response(val)

        elif sw == (0x90, 0x00):
            val = self.coms()[3]
            if len(val) > 0:
                return self._parse_auth_response(val)

        # Handle errors
        if self.dbg:
            if sw == (0x6D, 0x00):
                log(1, '(authenticate_isim) INS not supported - ISIM may not be selected')
            elif sw == (0x69, 0x82):
                log(1, '(authenticate_isim) Security status not satisfied')
            else:
                log(1, '(authenticate_isim) Failed with SW: %02X %02X' % (sw[0], sw[1]))

        return None

    def _parse_auth_response(self, data):
        """
        Parse AUTHENTICATE response data.

        Returns:
            [RES, CK, IK] on success
            [AUTS] on sync failure
            None on error
        """
        if not data or len(data) < 1:
            return None

        tag = data[0]

        # Tag 0xDB = successful authentication
        if tag == 0xDB:
            result = []
            idx = 1
            while idx < len(data):
                if idx >= len(data):
                    break
                length = data[idx]
                idx += 1
                if length == 0 or idx + length > len(data):
                    break
                value = list(data[idx:idx + length])
                result.append(value)
                idx += length
            return result if result else None

        # Tag 0xDC = synchronization failure
        elif tag == 0xDC:
            if len(data) >= 2:
                length = data[1]
                if len(data) >= 2 + length:
                    auts = list(data[2:2 + length])
                    return [auts]
            return None

        # No tag - try plain LV parsing
        else:
            result = []
            idx = 0
            while idx < len(data):
                if idx >= len(data):
                    break
                length = data[idx]
                idx += 1
                if length == 0 or idx + length > len(data):
                    break
                value = list(data[idx:idx + length])
                result.append(value)
                idx += length
            return result if result else None