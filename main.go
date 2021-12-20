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
	emailServer := os.Getenv("EMAIL_SERVER")
	emailUsername := os.Getenv("EMAIL_USERNAME")
	emailPassword := os.Getenv("EMAIL_PASSWORD")
	blockerHost := os.Getenv("BLOCKER_HOST")
	blockerPort := os.Getenv("BLOCKER_PORT")
	blockerAuthHeader := os.Getenv("BLOCKER_AUTH_HEADER")
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

	db, err := database.NewAbuseScannerDB(ctx, serverDomain, mongoUri, mongoCreds, logger)
	if err != nil {
		log.Fatal("Failed to initialize database client", err)
	}

	// create an email client
	logger.Info("Initializing email client...")
	mail, err := email.NewClient(emailServer, emailUsername, emailPassword)
	if err != nil {
		log.Fatal("Failed to initialize email client", err)
	}

	// defer logout
	defer func() {
		err := mail.Logout()
		if err != nil {
			logger.Infof("Failed logging out, error: %v", err)
		}
	}()

	// create a new mail fetcher, it downloads the emails
	logger.Info("Initializing email fetcher...")
	fetcher := email.NewFetcher(ctx, db, mail, abuseMailbox, logger)
	err = fetcher.Start()
	if err != nil {
		log.Fatal("Failed to start the email fetcher, err: ", err)
	}

	// create a new mail parser, it parses any email that's not parsed yet for
	// abuse skylinks and a set of abuse tag
	logger.Info("Initializing email parser...")
	parser := email.NewParser(ctx, db, abuseSponsor, logger)
	err = parser.Start()
	if err != nil {
		log.Fatal("Failed to start the email parser, err: ", err)
	}

	// create a new blocker, it blocks skylinks for any emails which have been
	// parsed but not blocked yet, it uses the blocker API for this.
	logger.Info("Initializing blocker...")
	blockerApiUrl := fmt.Sprintf("http://%s:%s", blockerHost, blockerPort)
	blocker := email.NewBlocker(ctx, blockerAuthHeader, blockerApiUrl, db, logger)
	err = blocker.Start()
	if err != nil {
		log.Fatal("Failed to start the blocker, err: ", err)
	}

	// create a new finalizer, it finalizes the abuse report for any emails
	// which are parsed, blocked, but not yet finalized. An email is finalized
	// when the abuse scanner has replied with a report of all the skylinks that
	// have been found and blocked.
	logger.Info("Initializing finalizer...")
	finalizer := email.NewFinalizer(ctx, db, mail, abuseMailaddress, abuseMailbox, logger)
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

// loadDBCredentials creates a new db connection based on credentials found in
// the environment variables.
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
