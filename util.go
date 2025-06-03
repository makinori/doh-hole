package main

import (
	"log"
	"time"
)

func RetryNoFail[T any](
	output *T,
	attempts int, waitDuration time.Duration,
	fn func() (T, error),
	errorMessagePrefix string,
) bool {
	var currentOutput T
	var lastError error

	attempt := 0

	for attempt < attempts {
		currentOutput, lastError = fn()

		if lastError == nil {
			// success
			*output = currentOutput
			return true
		}

		log.Printf(
			"failed %s (attempt %d): %s",
			errorMessagePrefix, attempt+1, lastError.Error(),
		)

		final := attempt == attempts-1
		if final {
			break
		}

		attempt++
		time.Sleep(waitDuration)
	}

	return false
}

func RetryNoFailNoOutput(
	attempts int, waitDuration time.Duration,
	fn func() error,
	errorMessagePrefix string,
) bool {
	var discard struct{}
	return RetryNoFail(
		&discard, attempts, waitDuration,
		func() (struct{}, error) {
			err := fn()
			return discard, err
		},
		errorMessagePrefix,
	)
}
