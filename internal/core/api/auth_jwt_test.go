package api

import (
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		// 合法密码
		{name: "valid password", password: "Abc123!@#", wantErr: false},
		{name: "valid complex", password: "P@ssw0rd2024!", wantErr: false},
		{name: "valid with special chars", password: "Test_123!@#", wantErr: false},
		// 太短
		{name: "too short", password: "Ab1!", wantErr: true},
		{name: "exactly 7 chars", password: "Ab1!def", wantErr: true},
		// 缺少大写字母
		{name: "missing upper", password: "abc123!@#", wantErr: true},
		// 缺少小写字母
		{name: "missing lower", password: "ABC123!@#", wantErr: true},
		// 缺少数字
		{name: "missing digit", password: "Abcdef!@#", wantErr: true},
		// 缺少特殊字符
		{name: "missing special", password: "Abcdef123", wantErr: true},
		// 空密码
		{name: "empty", password: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword_ErrorMessageContainsDetail(t *testing.T) {
	tests := []struct {
		password   string
		errContain string
	}{
		{"abc", "至少8个字符"},
		{"abcdefgh", "大写字母"},
		{"ABCDEFGH1!", "小写字母"},
		{"Abcdefgh!", "数字"},
		{"Abcdef123", "特殊字符"},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if err == nil {
				t.Fatalf("expected error for password %q", tt.password)
			}
			if !strings.Contains(err.Error(), tt.errContain) {
				t.Errorf("error message %q should contain %q", err.Error(), tt.errContain)
			}
		})
	}
}
