package pinblock

import (
    "strconv"
    "strings"
    "crypto/des"
    "crypto/cipher"
    "encoding/hex"
)

type PinSizeError int

func (p PinSizeError) Error() string {
    return "pinblock: invalid pin size " + strconv.Itoa(int(p))
}

type IsoFormatError int

func (p IsoFormatError) Error() string {
    return "pinblock: invalid ISO format " + strconv.Itoa(int(p))
}
/* ISO pin block types */
const (
    ISO_0 int = iota
    ISO_1
    ISO_3
)
/* Crypt operation defines */
const (
    encrypt int = iota
    decrypt
)

func bcd2dec(bcd []byte) uint64 {
    var i uint64 = 0
    for k := range bcd {
        r0 := bcd[k] & 0xf
        r1 := bcd[k] >> 4 & 0xf
        r := r1*10 + r0
        i = i*uint64(100) + uint64(r)
    }
    return i
}
/* Convert byte buffer to ASCII string */
func bcd2asc(bcd []byte, slen int) string {
    blen := int(slen/2) /* bcd buffer length */

    if slen % 2 != 0 {
        blen++
    }

    if blen > len(bcd) {
        return ""
    }

    b := make([]byte, slen)
    j := 0
    for i := 0; i < slen; i++ {
        if i % 2 == 0 {
            b[i] = bcd[j] >> 4
        } else {
            b[i] = (bcd[j] & 0x0f)
            j++
        }
        if b[i] < 10 {
            b[i] += '0'; // 0..9
        } else {
            b[i] += '7' // A..F
        }
    }

    return string(b)
}
/* Encrypt/Decrypt clear pin block */
func doCrypt(do int, key, dst, src []byte ) error {
    var err error
    var cipher cipher.Block

    if len(key) != 24 {
        var tripleDESKey []byte

        if len(key) == 16 {
            tripleDESKey = append(tripleDESKey, key[:16]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
        } else if len(key) == 8 {
            tripleDESKey = append(tripleDESKey, key[:8]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
        } else {
            return des.KeySizeError(len(key))
        }

        cipher, err = des.NewTripleDESCipher(tripleDESKey)

    } else {
        cipher, err = des.NewTripleDESCipher(key)
    }

    if err != nil {
        return err
    }

    if do == encrypt {
        cipher.Encrypt(dst, src)
    } else if do == decrypt {
        cipher.Decrypt(dst, src)
    }

    return nil
}
/* Get padded PIN by ISO type */
func getPaddedPin(isoType int, pin string) (string, error) {
    /* Get PIN length */
    plen := len(pin)
    /* Check incoming pin */
    if plen > 9 || plen < 1 {
        return "", PinSizeError(plen)
    }

    if isoType == ISO_0 {
        pin = "0" + strconv.Itoa(plen) + pin + strings.Repeat("F", 14 - plen)
    } else if isoType == ISO_1 {
        pin = "1" + string(plen) + pin
    } else if isoType == ISO_3 {
        pin = "3" + string(plen) + pin
    } else {
        return "", IsoFormatError(isoType)
    }

    return pin, nil
}
/* Prepare PAN (shifted) by ISO format */
func getShiftedPan(isoType int, pan string)(string, error){
    if isoType == ISO_0 {
        pan = "0000" + pan[len(pan)-13:][:12]
        return pan, nil
    }

    return "", IsoFormatError(isoType)
}
/* XOR PIN byte buffer with PAN byte buffer */
func getXoredPinPan(pin, pan []byte) []byte {
    /* Get encrypted/clear PIN block buffer size */
    n := len(pan)
    /* Create slice for xored data */
    b := make([]byte, n)
    /* Xor pin buffer with pan buffer */
    for i := 0; i < n; i++ {
        b[i] = pin[i] ^ pan[i]
    }

    return b
}

func getXoredPinPanStrings(pin, pan string) []byte {
    /* Decode PIN to byte buffer */
    pinHex, err := hex.DecodeString(pin)
    if err != nil {
        return nil
    }
    /* Decode shifted PAN to byte buffer */
    panHex, err := hex.DecodeString(pan)
    if err != nil {
        return nil
    }

    return getXoredPinPan(pinHex, panHex)
}
/***********************************************************************
 * Encrypt PIN by ISO format & return encrypted PIN block
 * as hex encoded string
 ***********************************************************************/
func EncryptPinBlock(isoType int, pin, pan, khex string) (string, error) {

    /* Create 3DES key */
    key, err := hex.DecodeString(khex)
    if err != nil {
        return "", err
    }
    /* Get padded PIN */
    pin, err = getPaddedPin(isoType, pin)
    if err != nil {
        return "", err
    }

    if isoType == ISO_0 || isoType == ISO_3 {
        /* Get shifted PAN */
        pan, err = getShiftedPan(isoType, pan)
        if err != nil {
            return "", err
        }
        /* Decode PIN to byte buffer */
        pinHex, err := hex.DecodeString(pin)
        if err != nil {
            return "", err
        }
        /* Decode shifted PAN to byte buffer */
        panHex, err := hex.DecodeString(pan)
        if err != nil {
            return "", err
        }
        /* Get encrypted buffer size */
        n := len(panHex)
        /* Create slice for xored data */
        b := make([]byte, n)
        /* Xor pin buffer with pan buffer */
        for i := 0; i < n; i++ {
            b[i] = pinHex[i] ^ panHex[i]
        }
        /* Create slice for encrypted buffer */
        pinBlock := make([]byte, len(b))
        /* Do PIN encryption */
        doCrypt(encrypt,key,pinBlock,b)
        /* Return hex encoded string */
        return hex.EncodeToString(pinBlock), nil
    }

    return "",IsoFormatError(isoType)
}
/***********************************************************************
 * Decrypt PIN by ISO format & return clear PIN from block
 * as hex encoded string
 ***********************************************************************/
func DecryptPinBlock(isoType int, pan, khex, pinBlockHex string) (string, error) {
    /* Create 3DES key */
    key, err := hex.DecodeString(khex)
    if err != nil {
        return "", err
    }
    /* Create encrypted PIN block byte buffer from hex string */
    pinBlockEnc, err := hex.DecodeString(pinBlockHex)
    if err != nil {
        return "", err
    }

    /* Create slice for clear PIN block */
    pinBlock := make([]byte, len(pinBlockEnc))
    /* Do PIN decryption */
    doCrypt(decrypt, key, pinBlock, pinBlockEnc)

    if isoType == ISO_0 || isoType == ISO_1 {
        /* Get shifted PAN by ISO format */
        pan, err = getShiftedPan(isoType, pan)
        if err != nil {
            return "", err
        }
        /* Decode to byte buffer */
        panHex, err := hex.DecodeString(pan)
        if err != nil {
            return "", err
        }
        /* Get clear PIN block buffer size */
        n := len(panHex)
        /* Create slice for xored data */
        b := make([]byte, n)
        /* Xor clear pinblock buffer with pan buffer */
        for i := 0; i < n; i++ {
            b[i] = pinBlock[i] ^ panHex[i]
        }
        /* Get first byte from xored buffer to read PIN length & ISO format */
        pl := bcd2dec(b[:1])

        if isoType == ISO_0 && pl > 10 {
            return "", IsoFormatError(pl)
        }
        /* Get PIN from buffer */
        pin := bcd2asc(b[1:], int(pl))

        return pin, nil
    }

    return "", IsoFormatError(isoType)
}

