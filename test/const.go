package test

import "os"

const (
	// MongoDBUsername is the username used to connect with the test DB.
	MongoDBUsername = "admin"

	// MongoDBPassword is the password used to connect with the test DB.
	MongoDBPassword = "aO4tV5tC1oU3oQ7u" // #nosec G101

	// MongoDBConnString is the connection string to connect with the test DB.
	MongoDBConnString = "mongodb://localhost:37017"
)

var (
	// TmpDir is the path to a temporary directory used by the parser.
	TmpDir = os.TempDir()
)
