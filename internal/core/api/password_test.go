package api

import (
	"testing"
)

func TestGenerateStrongPassword(t *testing.T) {
	// 生成 20 次密码，确保每次均符合强密码规范
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		pw, err := GenerateStrongPassword()
		if err != nil {
			t.Fatalf("GenerateStrongPassword() failed on iteration %d: %v", i, err)
		}
		if seen[pw] {
			t.Fatalf("GenerateStrongPassword() generated duplicate password on iteration %d", i)
		}
		seen[pw] = true

		// 验证密码符合 ValidateStrongPassword
		if err := ValidateStrongPassword(pw); err != nil {
			t.Fatalf("generated password failed validation on iteration %d: %v\npassword: %s", i, err, pw)
		}
	}
}

func TestGenerateStrongPassword_Length(t *testing.T) {
	for i := 0; i < 50; i++ {
		pw, err := GenerateStrongPassword()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pw) != MinPasswordLen {
			t.Errorf("expected length %d, got %d: %s", MinPasswordLen, len(pw), pw)
		}
	}
}

func TestValidateStrongPassword_Valid(t *testing.T) {
	validPasswords := []string{
		"MyS3cur3!Passw0rd",
		"abcdefGHIJKL!12345",
		"XyZ!2345678abcDEF",
		"!@Abcdefgh1234567",
	}

	for _, pw := range validPasswords {
		if err := ValidateStrongPassword(pw); err != nil {
			t.Errorf("expected valid password %q, got error: %v", pw, err)
		}
	}
}

func TestValidateStrongPassword_TooShort(t *testing.T) {
	pw := "Abc!1234567890" // 15 chars
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for too-short password")
	}
}

func TestValidateStrongPassword_NoUpper(t *testing.T) {
	pw := "abcdefgh!1234567"
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password missing uppercase")
	}
}

func TestValidateStrongPassword_NoLower(t *testing.T) {
	pw := "ABCDEFGH!1234567"
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password missing lowercase")
	}
}

func TestValidateStrongPassword_NoDigit(t *testing.T) {
	pw := "Abcdefgh!IJKLMNOP"
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password missing digit")
	}
}

func TestValidateStrongPassword_NoSpecialChar(t *testing.T) {
	pw := "Abcdefgh123456789"
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password missing special char")
	}
}

func TestValidateStrongPassword_ConsecutiveSameChars(t *testing.T) {
	pw := "Abc!1112345678901" // triple '1'
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password with 3 consecutive same chars")
	}
}

func TestValidateStrongPassword_UnsupportedChar(t *testing.T) {
	pw := "Abc!1234567890<>?" // '<' and '>' are not in specialChars
	err := ValidateStrongPassword(pw)
	if err == nil {
		t.Error("expected error for password with unsupported special char")
	}
}

func TestValidateStrongPassword_Empty(t *testing.T) {
	err := ValidateStrongPassword("")
	if err == nil {
		t.Error("expected error for empty password")
	}
}
