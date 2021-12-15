package database

import (
	"context"
	"fmt"

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
	coll := db.staticDatabase.Collection(collName)
	if coll == nil {
		err := db.staticDatabase.CreateCollection(ctx, collName)
		if err != nil {
			return nil, err
		}
		coll = db.staticDatabase.Collection(collName)
	}

	if coll == nil {
		return nil, fmt.Errorf("failed to ensure collection '%v'", collName)
	}
	return coll, nil
}
