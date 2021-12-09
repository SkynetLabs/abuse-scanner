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
	sponsor := os.Getenv("SKYNET_ABUSE_SPONSOR")
	loglevel := os.Getenv("LOG_LEVEL")

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
	d := email.NewFetcher(ctx, db, mail, email.MailboxInbox, logger)
	err = d.Start()
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

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	logger.Info("Terminated.")
	// // Select INBOX
	// mbox, err := c.Select("INBOX", false)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println("Flags for INBOX:", mbox.Flags)

	// // Get the last message
	// if mbox.Messages == 0 {
	// 	log.Fatal("No message in mailbox")
	// }
	// seqSet := new(imap.SeqSet)
	// seqSet.AddNum(mbox.Messages)

	// // Get the whole message body
	// var section imap.BodySectionName
	// items := []imap.FetchItem{section.FetchItem()}

	// messages := make(chan *imap.Message, 1)
	// go func() {
	// 	if err := c.Fetch(seqSet, items, messages); err != nil {
	// 		log.Fatal(err)
	// 	}
	// }()

	// msg := <-messages
	// if msg == nil {
	// 	log.Fatal("Server didn't returned message")
	// }

	// r := msg.GetBody(&section)
	// if r == nil {
	// 	log.Fatal("Server didn't returned message body")
	// }

	// // Create a new mail reader
	// mr, err := mail.CreateReader(r)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // Print some info about the message
	// header := mr.Header
	// if date, err := header.Date(); err == nil {
	// 	log.Println("Date:", date)
	// }
	// if from, err := header.AddressList("From"); err == nil {
	// 	log.Println("From:", from)
	// }
	// if to, err := header.AddressList("To"); err == nil {
	// 	log.Println("To:", to)
	// }
	// if subject, err := header.Subject(); err == nil {
	// 	log.Println("Subject:", subject)
	// }

	// // Process each message's part
	// for {
	// 	p, err := mr.NextPart()
	// 	if err == io.EOF {
	// 		break
	// 	} else if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	switch h := p.Header.(type) {
	// 	case *mail.InlineHeader:
	// 		// This is the message's text (can be plain-text or HTML)
	// 		b, _ := ioutil.ReadAll(p.Body)
	// 		log.Println("Got text: %v", string(b))
	// 	case *mail.AttachmentHeader:
	// 		// This is an attachment
	// 		filename, _ := h.Filename()
	// 		log.Println("Got attachment: %v", filename)
	// 	}
	// }

	// // Get the last 4 messages
	// from := uint32(1)
	// to := mbox.Messages
	// if mbox.Messages > 3 {
	// 	// We're using unsigned integers here, only subtract if the result is > 0
	// 	from = mbox.Messages - 3
	// }
	// seqset := new(imap.SeqSet)
	// seqset.AddRange(from, to)

	// // messages := make(chan *imap.Message, 10)
	// // done = make(chan error, 1)
	// // go func() {
	// // 	done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
	// // }()

	// // log.Println("Last 4 messages:")
	// // i := 0
	// // for msg := range messages {
	// // 	log.Println("* " + msg.Envelope.Subject)
	// // 	log.Println(i, "uid ", msg.Uid)
	// // 	log.Println(i, "subject "+msg.Envelope.Subject)
	// // 	log.Println(i, "flags ", msg.Flags)
	// // 	// if false {
	// // 		bodySection, _ := imap.ParseBodySectionName("BODY[]")
	// // 		log.Println("bodySection", bodySection)
	// // 		msgBody := msg.GetBody(bodySection)
	// // 		body, _ := ioutil.ReadAll(msgBody)
	// // 		log.Println("body", len(string(body)))
	// // 	}
	// // 	log.Println(i, "msg.raw body", msg.Body) //prints the header perfectly.
	// // 	headerSection, _ := imap.ParseBodySectionName("RFC822.HEADER")

	// // 	msgHeader := msg.GetBody(headerSection)
	// // 	if msgHeader == nil {
	// // 		log.Println(i, "msg header retrieve failed..")
	// // 	} else {
	// // 		headerBody, _ := ioutil.ReadAll(msgHeader)
	// // 		log.Println("headerBody", string(headerBody))
	// // 	}

	// // }

	// cmd, _ := c.UIDFetch(set, "RFC822.HEADER", "RFC822.TEXT")

	// // Process responses while the command is running
	// fmt.Println("\nMost recent messages:")
	// for cmd.InProgress() {
	// 	// Wait for the next response (no timeout)
	// 	c.Recv(-1)

	// 	// Process command data
	// 	for _, rsp = range cmd.Data {
	// 		header := imap.AsBytes(rsp.MessageInfo().Attrs["RFC822.HEADER"])
	// 		uid := imap.AsNumber((rsp.MessageInfo().Attrs["UID"]))
	// 		body := imap.AsBytes(rsp.MessageInfo().Attrs["RFC822.TEXT"])
	// 		if msg, _ := mail.ReadMessage(bytes.NewReader(header)); msg != nil {
	// 			fmt.Println("|--", msg.Header.Get("Subject"))
	// 			fmt.Println("UID: ", uid)

	// 			fmt.Println(string(body))
	// 		}
	// 	}
	// 	cmd.Data = nil
	// 	c.Data = nil
	// }

	// if err := <-done; err != nil {
	// 	log.Fatal(err)
	// }

	// log.Println("Done!")
}
