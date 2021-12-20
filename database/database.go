package database

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

type (
	// MongoDB represents a mongo database.
	MongoDB struct {
		staticClient   *mongo.Client
		staticDatabase *mongo.Database
		staticLogger   *logrus.Logger
		staticName     string
	}

	// dbSchema is a helper type that allows specifying a set of collections and
	// a corresponding index model for each collection
	dbSchema map[string][]mongo.IndexModel
)

// ensureSchema ensures the given database schema
func (db *MongoDB) ensureSchema(ctx context.Context, schema dbSchema) error {
	for collName, models := range schema {
		coll, err := db.ensureCollection(ctx, collName)
		if err != nil {
			return err
		}

		if models != nil {
			_, err = coll.Indexes().CreateMany(ctx, models)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureCollection ensures the collection with given name exists
func (db *MongoDB) ensureCollection(ctx context.Context, collName string) (*mongo.Collection, error) {
	err := db.staticDatabase.CreateCollection(ctx, collName)
	if err != nil && !isCollectionExists(err) {
		return nil, err
	}

	coll := db.staticDatabase.Collection(collName)
	return coll, nil
}

// isCollectionExists is a helper function that returns whether the given error
// contains the mongo collection already exists error message.
func isCollectionExists(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), mongoErrCollectionExists.Error())
}
