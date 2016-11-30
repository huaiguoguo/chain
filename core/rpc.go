package core

import (
	"context"
	"net/http"
	"strings"

	libcontext "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"chain/core/config"
	"chain/core/leader"
	"chain/core/pb"
	"chain/core/txdb"
	"chain/database/pg"
	"chain/errors"
	"chain/net/http/limit"
	"chain/net/http/reqid"
	"chain/protocol"
	"chain/protocol/bc"
)

type rpcServer struct {
	Config       *config.Config
	Chain        *protocol.Chain
	Store        *txdb.Store
	DB           pg.DB
	RequestLimit int
	Signer       func(context.Context, *bc.Block) ([]byte, error)
	Addr         string

	auth    *apiAuthn
	limiter *limit.BucketLimiter
}

func (r *rpcServer) Handler() http.Handler {
	r.auth = &apiAuthn{
		tokenMap: make(map[string]tokenResult),
	}
	r.limiter = limit.NewBucketLimiter(r.RequestLimit, 100)

	var opts []grpc.ServerOption

	opts = append(opts, grpc.RPCCompressor(grpc.NewGZIPCompressor()))
	opts = append(opts, grpc.RPCDecompressor(grpc.NewGZIPDecompressor()))
	opts = append(opts, grpc.UnaryInterceptor(r.unaryInterceptor))
	grpcServer := grpc.NewServer(opts...)

	pb.RegisterNodeServer(grpcServer, r)
	if r.Config != nil && r.Config.IsSigner {
		pb.RegisterSignerServer(grpcServer, r)
	}

	return grpcServer
}

func (r *rpcServer) GetBlock(ctx libcontext.Context, in *pb.GetBlockRequest) (*pb.GetBlockResponse, error) {
	err := <-r.Chain.BlockSoonWaiter(ctx, in.Height)
	if err != nil {
		return nil, errors.Wrapf(err, "waiting for block at height %d", in.Height)
	}

	rawBlock, err := r.Store.GetRawBlock(ctx, in.Height)
	if err != nil {
		return nil, err
	}

	return &pb.GetBlockResponse{Block: rawBlock}, nil
}

func (r *rpcServer) GetSnapshotInfo(ctx libcontext.Context, in *pb.Empty) (*pb.GetSnapshotInfoResponse, error) {
	height, size, err := r.Store.LatestSnapshotInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.GetSnapshotInfoResponse{
		Height:       height,
		Size:         size,
		BlockchainId: r.Config.BlockchainID[:],
	}, nil
}

func (r *rpcServer) GetSnapshot(ctx libcontext.Context, in *pb.GetSnapshotRequest) (*pb.GetSnapshotResponse, error) {
	data, err := r.Store.GetSnapshot(ctx, in.Height)
	if err != nil {
		return nil, err
	}

	return &pb.GetSnapshotResponse{Data: data}, nil
}

func (r *rpcServer) GetBlockHeight(ctx libcontext.Context, in *pb.Empty) (*pb.GetBlockHeightResponse, error) {
	return &pb.GetBlockHeightResponse{Height: r.Chain.Height()}, nil
}

func (r *rpcServer) SubmitTx(ctx libcontext.Context, in *pb.SubmitTxRequest) (*pb.SubmitTxResponse, error) {
	tx, err := bc.NewTxFromBytes(in.Transaction)
	if err != nil {
		return nil, err
	}
	err = r.Chain.AddTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	return &pb.SubmitTxResponse{Ok: true}, nil
}

func (r *rpcServer) SignBlock(ctx libcontext.Context, in *pb.SignBlockRequest) (*pb.SignBlockResponse, error) {
	if !leader.IsLeading() {
		addr, err := leader.Address(ctx, r.DB)
		if err != nil {
			return nil, errors.Wrap(err)
		}
		// Don't infinite loop if the leader's address is our own address.
		// This is possible if we just became the leader. The client should
		// just retry.
		if addr == r.Addr {
			return nil, errLeaderElection
		}

		conn, err := NewGRPCConn(addr, "")
		if err != nil {
			return nil, err
		}

		return pb.NewSignerClient(conn).SignBlock(ctx, in)
	}
	block, err := bc.NewBlockFromBytes(in.Block)
	if err != nil {
		return nil, err
	}
	sig, err := r.Signer(ctx, block)
	if err != nil {
		return nil, err
	}
	return &pb.SignBlockResponse{Signature: sig}, nil
}

func (r *rpcServer) unaryInterceptor(ctx libcontext.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx = reqid.NewContext(ctx, reqid.New())

	if err := r.limit(ctx); err != nil {
		return nil, err
	}

	if err := r.auth.authRPC(ctx); err != nil {
		return nil, err
	}

	resp, err := handler(ctx, req)
	if err != nil {
		detailedErr, _ := errInfo(err)
		resp = &pb.ErrorResponse{Error: protobufErr(detailedErr)}
	}
	return resp, nil
}

func (r *rpcServer) limit(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return errRateLimited
	}

	if !r.limiter.Allow(p.Addr.String()) {
		return errRateLimited
	}
	return nil
}

type coreCreds struct {
	Username, Password string
}

func newRPCCreds(token string) (credentials.PerRPCCredentials, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return nil, errors.New("invalid token string")
	}
	return &coreCreds{parts[0], parts[1]}, nil
}

func (c *coreCreds) GetRequestMetadata(ctx libcontext.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"username": c.Username,
		"password": c.Password,
	}, nil
}
func (c *coreCreds) RequireTransportSecurity() bool { return false }

func NewGRPCConn(addr, accesstoken string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if accesstoken != "" {
		creds, err := newRPCCreds(accesstoken)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	}
	opts = append(opts, grpc.WithCompressor(grpc.NewGZIPCompressor()))
	opts = append(opts, grpc.WithDecompressor(grpc.NewGZIPDecompressor()))
	if strings.HasPrefix(addr, "localhost") || strings.HasPrefix(addr, "127.0.0.1") || strings.HasPrefix(addr, ":") {
		opts = append(opts, grpc.WithInsecure())
	}

	return grpc.Dial(addr, opts...)
}
