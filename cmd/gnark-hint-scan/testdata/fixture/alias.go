package fixture

import gn "github.com/consensys/gnark/frontend"

func aliased(api gn.API) {
	api.Compiler().NewHint(knownHint, 1)
}
