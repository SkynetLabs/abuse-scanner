package main

import (
	"abuse-scanner/database"
	"abuse-scanner/email"
	"os/signal"
	"syscall"
	"time"

	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func main() {
	// load env
	_ = godotenv.Load()

	// create a context
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// fetch env variables
	emailServer := os.Getenv("EMAIL_SERVER")
	emailUsername := os.Getenv("EMAIL_USERNAME")
	emailPassword := os.Getenv("EMAIL_PASSWORD")
	mongoConnectionString := os.Getenv("MONGO_CONNECTIONSTRING")
	blockerApiUrl := os.Getenv("BLOCKER_API_URL")
	blockerAuthHeader := os.Getenv("BLOCKER_AUTH_HEADER")
	sponsor := os.Getenv("ABUSE_SPONSOR")
	loglevel := os.Getenv("ABUSE_LOG_LEVEL")

	// initialize a logger
	logger := logrus.New()

	// configure log level
	logLevel, err := logrus.ParseLevel(loglevel)
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
	db, err := database.NewAbuseScannerDB(ctx, mongoConnectionString, "localhost", logger)
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

	// create a new mail fetcher
	logger.Info("Initializing email fetcher...")
	f := email.NewFetcher(ctx, db, mail, email.MailboxInbox, logger)
	err = f.Start()
	if err != nil {
		log.Fatal("Failed to start the email fetcher", err)
		return
	}

	// create a new mail parser
	logger.Info("Initializing email parser...")
	p := email.NewParser(ctx, db, sponsor, logger)
	err = p.Start()
	if err != nil {
		log.Fatal("Failed to start the email parser", err)
		return
	}

	// create a new blocker
	logger.Info("Initializing blocker...")
	b := email.NewBlocker(ctx, blockerAuthHeader, blockerApiUrl, db, logger)
	err = b.Start()
	if err != nil {
		log.Fatal("Failed to start the email parser", err)
		return
	}

	// create a new finalizer
	logger.Info("Initializing finalizer...")
	_ = email.NewFinalizer(ctx, db, mail, email.MailboxInbox, email.MailboxAbuseScanner, logger)
	// err = f.Start()
	// if err != nil {
	// 	log.Fatal("Failed to start the email finalizer", err)
	// 	return
	// }

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	logger.Info("Terminated.")
}
