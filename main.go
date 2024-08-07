package main

import (
	"fmt"

	"github.com/yywing/esafenet-coder/coder"
)

func main() {
	encryptedData := "CGKFAICMPFGICCPHKFGGGBOMICMOKOBGPCBLKPCAHAGPFJHFABCPPKIOHIAIBJLLHJCODJMAGKBGIKDAFJHJMMKBDHABAJPBFNLBOIDFBHMMFKFHLPIAOPHEOAICJEMBCKFEIPGINHHBEGDOMEOPDKJGPNIJEDNOMEKLJHCGOJCEIPFPEDGBEHJLMNEEFIKFPGCCKCFCCOMONKACOEENLFIBAGNJBLHDNBBCNKNLDJINDOCEBFIKAEMNHAPLPHONDJGGEKJCBOIDHFLLFDJBDCMFIGMHFGNAPCKMPODJGCBIILMPALOAKIDGHCBNCEFAFEEEFGFNGDFIFCGCCF"
	decryptedData := `<?xml version="1.0" encoding="UTF-8" standalone="no"?><GetCDGAuthoriseTemplet><userId>SystemAdmin</userId><secretLevelId>1112233</secretLevelId></GetCDGAuthoriseTemplet>`

	decrypted, err := coder.Decrypt(encryptedData)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
	if decrypted != decryptedData {
		fmt.Println("dec error")
	}

	encrypted, err := coder.Encrypt(decryptedData)
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
	if encrypted != encryptedData {
		fmt.Println("enc error")
	}
}
