package domain

import "errors"

func GetInvalidTestRunError(errorMsg string) error {
	return errors.New("invalid test run, " + errorMsg)
}
