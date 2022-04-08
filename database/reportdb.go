package database

import (
	"context"
	"time"

	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	// resourceReports is the resource name used when locking reports
	resourceReports = "ncmec_reports"
)

type (
	// NCMECReport is a database entity that represents an NCMEC report.
	NCMECReport struct {
		ID      primitive.ObjectID `bson:"_id"`
		EmailID primitive.ObjectID `bson:"email_id"`

		Filed    bool      `bson:"filed"`
		FiledAt  time.Time `bson:"filed_at"`
		FiledErr string    `bson:"filed_err"`

		Report      string `bson:"report"`
		ReportID    uint64 `bson:"report_id"`
		ReportDebug bool   `bson:"report_debug"`

		InsertedAt time.Time `bson:"inserted_at"`
	}
)

// NewReportLock returns a lock on a report entity
func (db *AbuseScannerDB) NewReportLock(reportID string) *abuseLock {
	return db.newLockCustom(resourceReports, reportID)
}

// InsertReport will try and insert the given report into the database.
func (db *AbuseScannerDB) InsertReport(report NCMECReport) error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	coll := db.staticDatabase.Collection(collNCMECReports)
	_, err := coll.InsertOne(ctx, report)
	return err
}

// FindReport returns the report for given object id.
func (db *AbuseScannerDB) FindReport(reportID primitive.ObjectID) (*NCMECReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	coll := db.staticDatabase.Collection(collNCMECReports)
	res := coll.FindOne(ctx, bson.M{"_id": reportID})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}
	if res.Err() != nil {
		return nil, res.Err()
	}

	var report NCMECReport
	err := res.Decode(&report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// FindReports returns all NCMEC reports for the given abuse email id.
func (db *AbuseScannerDB) FindReports(emailID primitive.ObjectID) ([]NCMECReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	coll := db.staticDatabase.Collection(collNCMECReports)
	cursor, err := coll.Find(ctx, bson.M{"email_id": emailID})
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve reports")
	}

	var reports []NCMECReport
	err = cursor.All(ctx, &reports)
	if err != nil {
		db.staticLogger.Error("failed to decode NCMEC reports", err)
		return nil, err
	}

	return reports, nil
}

// FindUnfiledReports returns all NCMEC reports that have not been successfully
// filed yet, a report is filed once it's been successfully reported with NCMEC.
//
// NOTE: we do not retry when we failed to file a report successfully, before
// filing a report we ensure we can reach the NCMEC server using their status
// endpoint
func (db *AbuseScannerDB) FindUnfiledReports() ([]NCMECReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	coll := db.staticDatabase.Collection(collNCMECReports)
	cursor, err := coll.Find(ctx, bson.M{
		"filed":     false,
		"filed_err": "",
	})
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve reports")
	}

	var reports []NCMECReport
	err = cursor.All(ctx, &reports)
	if err != nil {
		db.staticLogger.Error("failed to decode NCMEC reports", err)
		return nil, err
	}

	return reports, nil
}

// UpdateReportNoLock will update the given report, this method does not lock
// the given report as it is expected for the caller to have acquired the lock.
func (db *AbuseScannerDB) UpdateReportNoLock(report NCMECReport, update interface{}) (err error) {
	// create a context with default timeout
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	reports := db.staticDatabase.Collection(collNCMECReports)
	_, err = reports.UpdateOne(ctx, bson.M{"_id": report.ID}, update)
	if err != nil {
		return err
	}

	return nil
}
