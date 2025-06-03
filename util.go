package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

func retryNoFail[T any](
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

func retryNoFailNoOutput(
	attempts int, waitDuration time.Duration,
	fn func() error,
	errorMessagePrefix string,
) bool {
	var discard struct{}
	return retryNoFail(
		&discard, attempts, waitDuration,
		func() (struct{}, error) {
			err := fn()
			return discard, err
		},
		errorMessagePrefix,
	)
}

func formatDuration(d time.Duration) string {
	out := []string{}

	hours := int(d.Hours())
	if hours > 0 {
		out = append(out, fmt.Sprintf("%dh", hours))
	}

	minutes := int(d.Minutes()) % 60
	if minutes > 0 {
		out = append(out, fmt.Sprintf("%dm", minutes))
	}

	seconds := int(d.Seconds()) % 60
	if seconds > 0 {
		out = append(out, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(out, " ")
}
