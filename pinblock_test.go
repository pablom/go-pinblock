package pinblock

import (
	"fmt"
	"testing"
)

const (
    TEST_PAN  string = "5364146259585156"
)

func TestPinBlock_length_4_2DES(t *testing.T) {

	var TEST_2DES_KEY = "0123456789ABCDEF0123456789ABCDEF"
	var TEST_PIN = "5810"
	var TEST_PBLOCK = "e1396de02a72d77a"

	pad_pin, _:= getPaddedPin(ISO_0, TEST_PIN)
	shift_pan, _:= getShiftedPan(ISO_0, TEST_PAN)
	clear_pb := getXoredPinPanStrings(pad_pin, shift_pan )

	pb, err := EncryptPinBlock(ISO_0, TEST_PIN, TEST_PAN, TEST_2DES_KEY)
	if err != nil {
		t.Fatalf("Failed to create PIN block ISO-0 format: %s\n", err)
	}

	if pb != TEST_PBLOCK {
		t.Fatalf("PIN block is incorrect: [%s], expected: [%s]\n", pb, TEST_PBLOCK)
	}

	fmt.Printf("\n----- PIN block information -----\n")
	fmt.Printf("Padded PIN          : %s\n", pad_pin)
	fmt.Printf("Shifted PAN         : %s\n", shift_pan)
	fmt.Printf("PIN block clear     : %x\n", string(clear_pb))
	fmt.Printf("PIN block           : %s\n\n", pb)

	/* Check decrypt PIN block */
	pin, err := DecryptPinBlock(ISO_0, TEST_PAN, TEST_2DES_KEY, pb)
	if err != nil {
		t.Fatalf("Failed to decrypt PIN block ISO-0 format: %s\n", err)
	}

	if pin != TEST_PIN {
		t.Fatalf("PIN is incorrect: [%s], expected: [%s]\n", pin, TEST_PIN)
	}
}

func TestPinBlock_length_5_2DES(t *testing.T) {
	var TEST_2DES_KEY = "0123456789ABCDEF0123456789ABCDEF"
	var TEST_PIN = "12347"
	var TEST_PBLOCK = "4d20494c51cacd59"

	pad_pin, _:= getPaddedPin(ISO_0, TEST_PIN)
	shift_pan, _:= getShiftedPan(ISO_0, TEST_PAN)
	clear_pb := getXoredPinPanStrings(pad_pin, shift_pan )

	pb, err := EncryptPinBlock(ISO_0, TEST_PIN, TEST_PAN, TEST_2DES_KEY)
	if err != nil {
		t.Fatalf("Failed to find RSA private key: %s\n", err)
	}

	if pb != TEST_PBLOCK {
		t.Fatalf("PIN block is incorrect: [%s], expected: [%s]\n", pb, TEST_PBLOCK)
	}

	fmt.Printf("\n----- PIN block information -----\n")
	fmt.Printf("Padded PIN          : %s\n", pad_pin)
	fmt.Printf("Shifted PAN         : %s\n", shift_pan)
	fmt.Printf("PIN block clear     : %x\n", string(clear_pb))
	fmt.Printf("PIN block           : %s\n\n", pb)

	/* Check decrypt PIN block */
	pin, err := DecryptPinBlock(ISO_0, TEST_PAN, TEST_2DES_KEY, pb)
	if err != nil {
		t.Fatalf("Failed to decrypt PIN block ISO-0 format: %s\n", err)
	}

	if pin != TEST_PIN {
		t.Fatalf("PIN is incorrect: [%s], expected: [%s]\n", pin, TEST_PIN)
	}
}

