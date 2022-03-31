package database

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	// email is a random email address used in testing
	email = "john.doe@example.com"

	// skylink is a random skylink used in testing
	skylink = "AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC"

	// userID is the id of the user we will insert in the setup
	userID primitive.ObjectID
)

// TestSkynetDB is the test suite that covers the SkynetDB
func TestSkynetDB(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	db, err := NewTestSkynetDB(ctx, t.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// insert a test upload
	err = db.InsertTestUpload(&SkynetUploadHydrated{
		SkynetUpload: SkynetUpload{
			UploaderIP: "13.192.32.50",
			Timestamp:  time.Now().UTC(),
		},
		Skylink: skylink,
		User: &SkynetUser{
			StripeID: "sub_123",
			Email:    email,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	// set the user ID
	user, err := db.FindUserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("expected user to be found")
	}
	userID = user.ID

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "FindUpload",
			test: func(t *testing.T) { testFindUpload(ctx, t, db) },
		},
		{
			name: "FindUploadsPerUser",
			test: func(t *testing.T) { testFindUploadsPerUser(ctx, t, db) },
		},
		{
			name: "FindUser",
			test: func(t *testing.T) { testFindUser(ctx, t, db) },
		},
		{
			name: "FindUserByEmail",
			test: func(t *testing.T) { testFindUserByEmail(ctx, t, db) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testFindUpload is a unit test for the method FindUpload.
func testFindUpload(ctx context.Context, t *testing.T, db *SkynetDB) {
	upload, err := db.FindUpload(skylink)
	if err != nil {
		t.Fatal(err)
	}

	var empty primitive.ObjectID
	if upload.UserID.Hex() == empty.Hex() {
		t.Fatal("expected user id to be set")
	}
	if upload.SkylinkID.Hex() == empty.Hex() {
		t.Fatal("expected skylink id to be set")
	}
	if upload.Skylink != skylink {
		t.Fatal("unexpected skylink", upload.Skylink)
	}
}

// testFindUploadsPerUser is a unit test for the method FindUploadsPerUser.
func testFindUploadsPerUser(ctx context.Context, t *testing.T, db *SkynetDB) {
	uploadsPerUser, err := db.FindUploadsPerUser([]string{skylink})
	if err != nil {
		t.Fatal(err)
	}
	if len(uploadsPerUser) != 1 {
		t.Fatalf("unexpected amount of users found, %v != 1", len(uploadsPerUser))
	}

	uploads, exists := uploadsPerUser[userID.Hex()]
	if !exists {
		t.Fatal("expected to find uploads for our test user")
	}

	if len(uploads) != 1 {
		t.Fatalf("unexpected amount of uploads found, %v != 1", len(uploads))
	}

	upload := uploads[0]
	if upload.Skylink != skylink {
		t.Fatal("unexpected upload found", upload)
	}
}

// testFindUser is a unit test for the method FindUser.
func testFindUser(ctx context.Context, t *testing.T, db *SkynetDB) {
	user, err := db.FindUser(userID)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("expected to find our test user")
	}
	if user.Email != email {
		t.Fatal("unexpected user returned", user)
	}

	randomID := primitive.NewObjectID()
	user, err = db.FindUser(randomID)
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatal("unexpected user found", user)
	}
}

// testFindUserByEmail is a unit test for the method FindUserByEmail.
func testFindUserByEmail(ctx context.Context, t *testing.T, db *SkynetDB) {
	user, err := db.FindUserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("expected to find our test user")
	}
	if user.Email != email {
		t.Fatal("unexpected user returned", user)
	}

	randomEmail := email + "random"
	user, err = db.FindUserByEmail(randomEmail)
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatal("unexpected user found", user)
	}
}
