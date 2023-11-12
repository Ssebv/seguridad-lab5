package main

import (
	"math/big"
)

func mod(base, exp, mod *big.Int) *big.Int {
	result := new(big.Int).SetInt64(1)
	zero := new(big.Int)

	base = new(big.Int).Mod(base, mod)

	for exp.Cmp(zero) > 0 {
		if exp.Bit(0) == 1 {
			result = new(big.Int).Mod(new(big.Int).Mul(result, base), mod)
		}
		exp = new(big.Int).Rsh(exp, 1)
		base = new(big.Int).Mod(new(big.Int).Mul(base, base), mod)
	}

	return result
}

func main() {

}
