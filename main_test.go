package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gitlab.com/NebulousLabs/errors"
)

// TestLoadDBCredentials is a unit test that covers the loadDBCredentials
// helper.
func TestLoadDBCredentials(t *testing.T) {
	variables := []string{
		"SKYNET_DB_USER",
		"SKYNET_DB_PASS",
		"SKYNET_DB_HOST",
		"SKYNET_DB_PORT",
	}

	// create a function to restore the environment
	restoreEnvFn := restoreEnv(variables)
	defer func() {
		err := restoreEnvFn()
		if err != nil {
			t.Error(err)
		}
	}()

	// set every env variable to its name
	for _, variable := range variables {
		os.Setenv(variable, variable)
	}

	// load db credentials and assert its output (happy case)
	connstring, credentials, err := loadDBCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Username != "SKYNET_DB_USER" || credentials.Password != "SKYNET_DB_PASS" {
		t.Fatal("unexpected", credentials)
	}
	if connstring != "mongodb://SKYNET_DB_HOST:SKYNET_DB_PORT" {
		t.Fatal("unexpected", connstring)
	}

	// unset every env variable one by one and assert the helper indicates what
	// environment variable is missing
	for _, variable := range variables {
		bkp := os.Getenv(variable)
		err = os.Unsetenv(variable)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err := loadDBCredentials()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("missing env var %v", variable)) {
			t.Fatal("unexpected outcome", err)
		}

		// put it back
		err = os.Setenv(variable, bkp)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestLoadEmailCredentials is a unit test that covers the loadEmailCredentials
// helper.
func TestLoadEmailCredentials(t *testing.T) {
	variables := []string{
		"EMAIL_SERVER",
		"EMAIL_USERNAME",
		"EMAIL_PASSWORD",
	}

	// create a function to restore the environment
	restoreEnvFn := restoreEnv(variables)
	defer func() {
		err := restoreEnvFn()
		if err != nil {
			t.Error(err)
		}
	}()

	// set every env variable to its name
	for _, variable := range variables {
		os.Setenv(variable, variable)
	}

	// load email credentials and assert its output (happy case)
	credentials, err := loadEmailCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Address != "EMAIL_SERVER" || credentials.Username != "EMAIL_USERNAME" || credentials.Password != "EMAIL_PASSWORD" {
		t.Fatal("unexpected", credentials)
	}

	// unset every env variable one by one and assert the helper indicates what
	// environment variable is missing
	for _, variable := range variables {
		bkp := os.Getenv(variable)
		err = os.Unsetenv(variable)
		if err != nil {
			t.Fatal(err)
		}

		_, err := loadEmailCredentials()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("missing env var '%v'", variable)) {
			t.Fatal("unexpected outcome", variable, err)
		}

		// put it back
		err = os.Setenv(variable, bkp)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRestoreEnv is small unit test that covers the restoreEnv helper
func TestRestoreEnv(t *testing.T) {
	// assert it can handle nil
	restoreFn := restoreEnv(nil)
	err := restoreFn()
	if err != nil {
		t.Fatal(err)
	}

	// set an env variable to some value
	varName := "TestRestoreEnv"
	err = os.Setenv(varName, "somevalue")
	if err != nil {
		t.Fatal(err)
	}

	// create the function
	restoreFn = restoreEnv([]string{varName})

	// update the env variable and assert it's set
	os.Setenv(varName, "somenewvalue")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(varName) != "somenewvalue" {
		t.Fatal("unexpected", os.Getenv(varName))
	}

	// restore the env and assert it got restored
	err = restoreFn()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(varName) != "somevalue" {
		t.Fatal("unexpected", os.Getenv(varName))
	}
}

// restoreEnv is a helper function that returns a function that, when executed,
// restores the environment to the point restoreEnv got called. It restores the
// environment only for the given set of environment variable names.
func restoreEnv(variables []string) func() error {
	backup := make(map[string]string)
	for _, variable := range variables {
		value, exists := os.LookupEnv(variable)
		if exists {
			backup[variable] = value
		}
	}
	return func() error {
		var errs []error
		for _, variable := range variables {
			original, exists := backup[variable]
			if !exists {
				if err := os.Unsetenv(variable); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if err := os.Setenv(variable, original); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Compose(errs...)
	}
}
