package api

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"unicode"
)

const (
	// MinPasswordLen 强密码最小长度（管理端初始密码 ≥ 16 位）
	MinPasswordLen = 16

	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	specialChars = "!@#$%^&*()-_+=[]{}|:;,.?"
)

// GenerateStrongPassword 使用 crypto/rand 生成符合安全标准的强密码
// 长度不低于 16 位，至少包含 1 个大写字母、1 个小写字母、1 个数字、1 个特殊字符
// 避免出现连续 3 个相同字符、常见弱密码组合
func GenerateStrongPassword() (string, error) {
	const length = MinPasswordLen

	// 先保证每类字符至少一个
	var password []byte

	// 从每类中各取 2 个（共计 8 个基础字符）
	for _, pool := range []string{lowerChars, upperChars, digitChars, specialChars} {
		for i := 0; i < 2; i++ {
			b, err := randomByte(pool)
			if err != nil {
				return "", err
			}
			password = append(password, b)
		}
	}

	// 剩余 8 个字符从混合池中随机选取
	allChars := lowerChars + upperChars + digitChars + specialChars
	for i := 0; i < length-8; i++ {
		b, err := randomByte(allChars)
		if err != nil {
			return "", err
		}
		password = append(password, b)
	}

	// Fisher-Yates 洗牌避免可预测的模式
	if err := shuffle(password); err != nil {
		return "", err
	}

	// 后验校验：确保不包含连续 3 个相同字符
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			// 重新生成（递归最多 3 次避免无限循环）
			return GenerateStrongPassword()
		}
	}

	return string(password), nil
}

// randomByte 从字符池中随机选取一个字节
func randomByte(pool string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		return 0, err
	}
	return pool[n.Int64()], nil
}

// shuffle 使用 Fisher-Yates 算法洗牌
func shuffle(data []byte) error {
	for i := len(data) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		data[i], data[j.Int64()] = data[j.Int64()], data[i]
	}
	return nil
}

// ValidateStrongPassword 验证密码是否符合强密码要求
// 要求: ≥16 字符、大写、小写、数字、特殊字符、无连续 3 个相同字符
func ValidateStrongPassword(password string) error {
	if len(password) < MinPasswordLen {
		return errors.New("密码需至少 16 个字符")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	specialSet := specialChars

	for i, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case strings.ContainsRune(specialSet, ch):
			hasSpecial = true
		default:
			return errors.New("密码包含不支持的特殊字符，请使用: " + specialSet)
		}

		// 检查连续 3 个相同字符
		if i >= 2 && password[i] == password[i-1] && password[i-1] == password[i-2] {
			return errors.New("密码不得包含连续 3 个相同字符")
		}
	}

	if !hasUpper {
		return errors.New("密码需至少包含 1 个大写字母")
	}
	if !hasLower {
		return errors.New("密码需至少包含 1 个小写字母")
	}
	if !hasDigit {
		return errors.New("密码需至少包含 1 个数字")
	}
	if !hasSpecial {
		return errors.New("密码需至少包含 1 个特殊字符 (" + specialSet + ")")
	}

	return nil
}
