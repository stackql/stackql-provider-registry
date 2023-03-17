package nomenclature

import (
	"fmt"
	"strings"
)

const (
	FallbackProviderVersionTag string = "v00.00.00000"
)

type ProviderDesignation struct {
	Name string
	Tag  string
	Sha  string
}

func ExtractProviderDesignation(providerStr string) (ProviderDesignation, error) {
	return extractProviderDesignation(providerStr)
}

func extractProviderDesignation(providerStr string) (ProviderDesignation, error) {
	if strings.Contains(providerStr, ":") {
		splitDes := strings.Split(providerStr, ":")
		if len(splitDes) != 2 {
			return ProviderDesignation{}, fmt.Errorf("provider ID only allowed to contain 1 x '%s' character", ":")
		}
		return ProviderDesignation{
			Name: splitDes[0],
			Tag:  splitDes[1],
			Sha:  "",
		}, nil
	}
	if strings.Contains(providerStr, "@") {
		splitDes := strings.Split(providerStr, "@")
		if len(splitDes) != 2 {
			return ProviderDesignation{}, fmt.Errorf("provider ID only allowed to contain 1 x '%s' character", "@")
		}
		return ProviderDesignation{
			Name: splitDes[0],
			Tag:  "",
			Sha:  splitDes[1],
		}, nil
	}
	return ProviderDesignation{
		Name: providerStr,
		Tag:  FallbackProviderVersionTag,
		Sha:  "",
	}, nil
}
