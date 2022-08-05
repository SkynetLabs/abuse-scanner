package main

import (
	"abuse-scanner/accounts"
	"abuse-scanner/database"
	"abuse-scanner/email"
	"abuse-scanner/utils"
	"fmt"
	"os/signal"
	"strconv"
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
	abusePortalURL := utils.SanitizeURL(os.Getenv("ABUSE_PORTAL_URL"))
	abuseSponsor := os.Getenv("ABUSE_SPONSOR")
	abuseTmpDir := os.Getenv("ABUSE_TMP_DIR")
	accountsHost := os.Getenv("SKYNET_ACCOUNTS_HOST")
	accountsPort := os.Getenv("SKYNET_ACCOUNTS_PORT")
	blockerHost := os.Getenv("BLOCKER_HOST")
	blockerPort := os.Getenv("BLOCKER_PORT")
	serverDomain := os.Getenv("SERVER_DOMAIN")

	// use a default for the abuse directory if it's not set
	if abuseTmpDir == "" {
		abuseTmpDir = "/tmp/abuse-scanner"
	}

	// parse ncmec reporting enabled variable
	ncmecReportingEnabled := false
	ncmecReportingEnabledStr := os.Getenv("ABUSE_NCMEC_REPORTING_ENABLED")
	if ncmecReportingEnabledStr != "" {
		var err error
		ncmecReportingEnabled, err = strconv.ParseBool(ncmecReportingEnabledStr)
		if err != nil {
			log.Fatalf("Failed parsing the value for env variable ABUSE_NCMEC_REPORTING_ENABLED '%s' as a boolean, err %v", ncmecReportingEnabledStr, err)
		}
	}

	// TODO: validate env variables

	// sanitize the inputs
	abuseMailbox = strings.Trim(abuseMailbox, "\"")
	abuseSponsor = strings.Trim(abuseSponsor, "\"")

	// load email credentials
	emailCredentials, err := loadEmailCredentials()
	if err != nil {
		log.Fatal("Failed to load email credentials", err)
	}

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
	abuseDB, err := database.NewAbuseScannerDB(ctx, serverDomain, database.DBAbuseScanner, mongoUri, mongoCreds, logger)
	if err != nil {
		log.Fatalf("Failed to initialize database client, err: %v", err)
	}

	// create a new mail fetcher, it downloads the emails
	logger.Info("Initializing email fetcher...")
	fetcher := email.NewFetcher(ctx, abuseDB, emailCredentials, abuseMailbox, serverDomain, logger)
	err = fetcher.Start()
	if err != nil {
		log.Fatal("Failed to start the email fetcher, err: ", err)
	}

	// create a new mail parser, it parses any email that's not parsed yet for
	// abuse skylinks and a set of abuse tag
	logger.Info("Initializing email parser...")
	parser := email.NewParser(ctx, abuseDB, serverDomain, abuseSponsor, abuseTmpDir, logger)
	err = parser.Start()
	if err != nil {
		log.Fatal("Failed to start the email parser, err: ", err)
	}

	// create a new blocker, it blocks skylinks for any emails which have been
	// parsed but not blocked yet, it uses the blocker API for this.
	logger.Info("Initializing blocker...")
	blockerApiUrl := fmt.Sprintf("http://%s:%s", blockerHost, blockerPort)
	blocker := email.NewBlocker(ctx, blockerApiUrl, serverDomain, abuseDB, logger)
	err = blocker.Start()
	if err != nil {
		log.Fatal("Failed to start the blocker, err: ", err)
	}

	// create a new finalizer, it finalizes the abuse report for any emails
	// which are parsed, blocked, but not yet finalized. An email is finalized
	// when the abuse scanner has replied with a report of all the skylinks that
	// have been found and blocked.
	logger.Info("Initializing finalizer...")
	finalizer := email.NewFinalizer(ctx, abuseDB, emailCredentials, abuseMailaddress, abuseMailbox, serverDomain, logger)
	err = finalizer.Start()
	if err != nil {
		log.Fatal("Failed to start the email finalizer, err: ", err)
	}

	// create a new reporter, it will scan for emails that contain CSAM and
	// report those instances to NCMEC.
	var reporter *email.Reporter
	if ncmecReportingEnabled {
		// load NCMEC credentials
		ncmecCredentials, err := email.LoadNCMECCredentials()
		if err != nil {
			log.Fatal("Failed to load NCMEC credentials", err)
		}

		// load NCMEC reporter
		ncmecReporter, err := email.LoadNCMECReporter()
		if err != nil {
			log.Fatal("Failed to load NCMEC reporter", err)
		}

		// create an accounts client
		accountsClient := accounts.NewAccountsClient(accountsHost, accountsPort)

		logger.Info("Initializing reporter...")
		reporter := email.NewReporter(abuseDB, accountsClient, ncmecCredentials, abusePortalURL, serverDomain, ncmecReporter, logger)
		err = reporter.Start()
		if err != nil {
			log.Fatal("Failed to start the NCMEC reporter, err: ", err)
		}
	}

	// catch exit signals
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// on exit call cancel and stop all components
	cancel()
	err = errors.Compose(
		abuseDB.Close(),
		fetcher.Stop(),
		parser.Stop(),
		blocker.Stop(),
		finalizer.Stop(),
	)
	if reporter != nil {
		err = errors.Compose(
			err,
			reporter.Stop(),
		)
	}
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
