package core

import (
	"testing"

	"golang.org/x/net/context"

	"chain/core/asset/assettest"
	"chain/database/pg"
	"chain/database/pg/pgtest"
	"chain/net/http/authn"
)

func TestCreateAPIToken(t *testing.T) {
	ctx := pg.NewContext(context.Background(), pgtest.NewTx(t))

	uid := assettest.CreateUserFixture(ctx, t, "foo@bar.com", "abracadabra")
	ctx = authn.NewContext(ctx, uid)

	tok, err := createAPIToken(ctx)
	if err != nil {
		t.Fatal("unexpected error", err)
	}

	// Verify that the token is valid
	gotUID, err := authenticateToken(ctx, tok.ID, tok.Secret)
	if err != nil {
		t.Errorf("authenticate token err = %v want nil", err)
	}
	if gotUID != uid {
		t.Errorf("authenticated user ID = %v want %v", gotUID, uid)
	}
}