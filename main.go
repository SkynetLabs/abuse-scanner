package main

import (
	"abuse-scanner/database"
	"abuse-scanner/email"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// load env
	_ = godotenv.Load()

	// create a context
	ctx, cancel := context.WithCancel(context.Background())

	// fetch env variables
	abuseLoglevel := os.Getenv("ABUSE_LOG_LEVEL")
	abuseMailaddress := os.Getenv("ABUSE_MAILADDRESS")
	abuseMailbox := os.Getenv("ABUSE_MAILBOX")
	abuseSponsor := os.Getenv("ABUSE_SPONSOR")
	blockerHost := os.Getenv("BLOCKER_HOST")
	blockerPort := os.Getenv("BLOCKER_PORT")
	serverDomain := os.Getenv("SERVER_DOMAIN")

	// TODO: validate env variables

	// sanitize the inputs
	abuseMailbox = strings.Trim(abuseMailbox, "\"")
	abuseSponsor = strings.Trim(abuseSponsor, "\"")

	// initialize a logger
	logger := logrus.New()

	// configure log level
	logLevel, err := logrus.ParseLevel(abuseLoglevel)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// configure log formatter
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = "2006-01-02 15:04:05"
	formatter.FullTimestamp = true
	logger.SetFormatter(formatter)

	// create a database client
	mongoUri, mongoCreds, err := loadDBCredentials()
	if err != nil {
		log.Fatal("Failed to load mongo database credentials", err)
	}

	// create a database instance
	db, err := database.NewAbuseScannerDB(ctx, serverDomain, mongoUri, database.DBAbuseScanner, mongoCreds, logger)
	if err != nil {
		log.Fatalf("Failed to initialize database client, err: %v", err)
	}

	// load email credentials
	emailCredentials, err := loadEmailCredentials()
	if err != nil {
		log.Fatal("Failed to load email credentials", err)
	}

	// create a new mail fetcher, it downloads the emails
	logger.Info("Initializing email fetcher...")
	fetcher := email.NewFetcher(ctx, db, emailCredentials, abuseMailbox, serverDomain, logger)
	err = fetcher.Start()
	if err != nil {
		log.Fatal("Failed to start the email fetcher, err: ", err)
	}

	// create a new mail parser, it parses any email that's not parsed yet for
	// abuse skylinks and a set of abuse tag
	logger.Info("Initializing email parser...")
	parser := email.NewParser(ctx, db, serverDomain, abuseSponsor, logger)
	err = parser.Start()
	if err != nil {
		log.Fatal("Failed to start the email parser, err: ", err)
	}

	// create a new blocker, it blocks skylinks for any emails which have been
	// parsed but not blocked yet, it uses the blocker API for this.
	logger.Info("Initializing blocker...")
	blockerApiUrl := fmt.Sprintf("http://%s:%s", blockerHost, blockerPort)
	blocker := email.NewBlocker(ctx, blockerApiUrl, db, logger)
	err = blocker.Start()
	if err != nil {
		log.Fatal("Failed to start the blocker, err: ", err)
	}

	// create a new finalizer, it finalizes the abuse report for any emails
	// which are parsed, blocked, but not yet finalized. An email is finalized
	// when the abuse scanner has replied with a report of all the skylinks that
	// have been found and blocked.
	logger.Info("Initializing finalizer...")
	finalizer := email.NewFinalizer(ctx, db, emailCredentials, abuseMailaddress, abuseMailbox, serverDomain, logger)
	err = finalizer.Start()
	if err != nil {
		log.Fatal("Failed to start the email finalizer, err: ", err)
	}

	// catch exit signals
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// on exit call cancel and stop all components
	cancel()
	err = errors.Compose(
		db.Close(),
		fetcher.Stop(),
		parser.Stop(),
		blocker.Stop(),
		finalizer.Stop(),
	)
	if err != nil {
		log.Fatal("Failed to cleanly close all components, err: ", err)
	}

	logger.Info("Abuse Scanner Terminated.")
}

// loadDBCredentials is a helper function that loads the mongo db credentials
// from the environment. If any of the values are empty, it returns an error
// that indicates what env variable is missing.
func loadDBCredentials() (string, options.Credential, error) {
	var creds options.Credential
	var ok bool
	if creds.Username, ok = os.LookupEnv("SKYNET_DB_USER"); !ok {
		return "", options.Credential{}, errors.New("missing env var SKYNET_DB_USER")
	}
	if creds.Password, ok = os.LookupEnv("SKYNET_DB_PASS"); !ok {
		return "", options.Credential{}, errors.New("missing env var SKYNET_DB_PASS")
	}
	var host, port string
	if host, ok = os.LookupEnv("SKYNET_DB_HOST"); !ok {
		return "", options.Credential{}, errors.New("missing env var SKYNET_DB_HOST")
	}
	if port, ok = os.LookupEnv("SKYNET_DB_PORT"); !ok {
		return "", options.Credential{}, errors.New("missing env var SKYNET_DB_PORT")
	}
	return fmt.Sprintf("mongodb://%v:%v", host, port), creds, nil
}

// loadEmailCredentials is a helper function that loads the email credentials
// from the environment. If any of the values are empty, it returns an error
// that indicates what env variable is missing.
func loadEmailCredentials() (email.Credentials, error) {
	var creds email.Credentials
	var ok bool
	if creds.Address, ok = os.LookupEnv("EMAIL_SERVER"); !ok {
		return email.Credentials{}, errors.New("missing env var 'EMAIL_SERVER'")
	}
	if creds.Username, ok = os.LookupEnv("EMAIL_USERNAME"); !ok {
		return email.Credentials{}, errors.New("missing env var 'EMAIL_USERNAME'")
	}
	if creds.Password, ok = os.LookupEnv("EMAIL_PASSWORD"); !ok {
		return email.Credentials{}, errors.New("missing env var 'EMAIL_PASSWORD'")
	}
	return creds, nil
}
