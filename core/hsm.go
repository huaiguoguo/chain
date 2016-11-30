package core

import (
	"context"

	"chain/core/mockhsm"
	"chain/core/pb"
	"chain/core/txbuilder"
	"chain/crypto/ed25519/chainkd"
	"chain/errors"
)

func (h *Handler) CreateKey(ctx context.Context, in *pb.CreateKeyRequest) (*pb.CreateKeyResponse, error) {
	result, err := h.HSM.XCreate(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	xpub := &pb.XPub{Xpub: result.XPub[:]}
	if result.Alias != nil {
		xpub.Alias = *result.Alias
	}
	return &pb.CreateKeyResponse{Xpub: xpub}, nil
}

func (h *Handler) ListKeys(ctx context.Context, in *pb.ListKeysQuery) (*pb.ListKeysResponse, error) {
	limit := defGenericPageSize

	xpubs, after, err := h.HSM.ListKeys(ctx, in.Aliases, in.After, limit)
	if err != nil {
		return nil, err
	}

	var items []*pb.XPub
	for _, xpub := range xpubs {
		proto := &pb.XPub{Xpub: xpub.XPub[:]}
		if xpub.Alias != nil {
			proto.Alias = *xpub.Alias
		}
		items = append(items, proto)
	}

	in.After = after

	return &pb.ListKeysResponse{
		Items:    items,
		LastPage: len(xpubs) < limit,
		Next:     in,
	}, nil
}

func (h *Handler) DeleteKey(ctx context.Context, in *pb.DeleteKeyRequest) (*pb.ErrorResponse, error) {
	var key chainkd.XPub
	if len(in.Xpub) != len(key) {
		return nil, chainkd.ErrBadKeyLen
	}
	copy(key[:], in.Xpub)
	return nil, h.HSM.DeleteChainKDKey(ctx, key)
}

func (h *Handler) mockhsmSignTemplates(ctx context.Context, x struct {
	Txs   []*txbuilder.Template `json:"transactions"`
	XPubs []string              `json:"xpubs"`
}) []interface{} {
	resp := make([]interface{}, 0, len(x.Txs))
	for _, tx := range x.Txs {
		err := txbuilder.Sign(ctx, tx, x.XPubs, h.mockhsmSignTemplate)
		if err != nil {
			info, _ := errInfo(err)
			resp = append(resp, info)
		} else {
			resp = append(resp, tx)
		}
	}
	return resp
}

func (h *Handler) mockhsmSignTemplate(ctx context.Context, xpubstr string, path [][]byte, data [32]byte) ([]byte, error) {
	var xpub chainkd.XPub
	err := xpub.UnmarshalText([]byte(xpubstr))
	if err != nil {
		return nil, errors.Wrap(err, "parsing xpub")
	}
	sigBytes, err := h.HSM.XSign(ctx, xpub, path, data[:])
	if err == mockhsm.ErrNoKey {
		return nil, nil
	}
	return sigBytes, err
}
