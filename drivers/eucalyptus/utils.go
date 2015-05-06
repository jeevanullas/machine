package eucalyptus

import (
	"errors"
)

var (
	errInvalidRegion  = errors.New("invalid region specified")
	errMachineFailure = errors.New("Machine failed to start")
	errNoIP           = errors.New("No IP Address associated with the instance")
	errComplete       = errors.New("Complete")
)

type region struct {
	AmiId string
}

var regionDetails map[string]*region = map[string]*region{
	"eucalyptus": {"emi-1ec34ef2"},
}

func awsRegionsList() []string {
	var list []string

	for k := range regionDetails {
		list = append(list, k)
	}

	return list
}

func validateAwsRegion(region string) (string, error) {
	for _, v := range awsRegionsList() {
		if v == region {
			return region, nil
		}
	}

	return "", errInvalidRegion
}
