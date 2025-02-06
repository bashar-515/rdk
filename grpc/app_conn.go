package grpc

import (
	"context"
	"net/url"
	"time"

	"go.viam.com/utils"
	"go.viam.com/utils/rpc"

	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/utils/contextutils"
)

// AppConn maintains an underlying client connection meant to be used globally to connect to App. The `AppConn` constructor repeatedly
// attempts to dial App until a connection is successfully established.
type AppConn struct {
	*ReconfigurableClientConn

	dialer *utils.StoppableWorkers
}

// NewAppConn creates an `AppConn` instance with a gRPC client connection to App. An initial dial attempt blocks. If it errors, the error
// is returned. If it times out, an `AppConn` object with a nil underlying client connection will return. Serialized attempts at
// establishing a connection to App will continue to occur, however, in a background Goroutine. These attempts will continue until a
// connection is made. If `cloud` is nil, an `AppConn` with a nil underlying connection will return, and the background dialer will not
// start.
func NewAppConn(ctx context.Context, appAddress, secret, id string, logger logging.Logger) (rpc.ClientConn, error) {
	appConn := &AppConn{}

	grpcURL, err := url.Parse(appAddress)
	if err != nil {
		return nil, err
	}

	dialOpts := dialOpts(secret, id)

	if grpcURL.Scheme == "http" {
		dialOpts = append(dialOpts, rpc.WithInsecure())
	}

	ctxWithTimeout, ctxWithTimeoutCancel := contextutils.GetTimeoutCtx(ctx, true, id)
	defer ctxWithTimeoutCancel()

	// lock not necessary here because call is blocking
	appConn.conn, err = rpc.DialDirectGRPC(ctxWithTimeout, grpcURL.Host, logger, dialOpts...)
	if err == nil {
		return appConn, nil
	}

	appConn.dialer = utils.NewStoppableWorkers(ctx)

	appConn.dialer.Add(func(ctx context.Context) {
		for {
			if ctx.Err() != nil {
				return
			}

			ctxWithTimeout, ctxWithTimeoutCancel := context.WithTimeout(ctx, 5*time.Second)
			conn, err := rpc.DialDirectGRPC(ctxWithTimeout, grpcURL.Host, logger, dialOpts...)
			ctxWithTimeoutCancel()
			if err != nil {
				logger.Debugw("error while dialing App. Could not establish global, unified connection", "error", err)

				continue
			}

			appConn.connMu.Lock()
			appConn.conn = conn
			appConn.connMu.Unlock()

			return
		}
	})

	return appConn, nil
}

// Close attempts to close the underlying connection and stops background dialing attempts.
func (ac *AppConn) Close() error {
	if ac.dialer != nil {
		ac.dialer.Stop()
	}

	return ac.ReconfigurableClientConn.Close()
}

func dialOpts(secret, id string) []rpc.DialOption {
	dialOpts := make([]rpc.DialOption, 0, 2)
	// Only add credentials when secret is set.
	if secret != "" {
		dialOpts = append(dialOpts, rpc.WithEntityCredentials(id,
			rpc.Credentials{
				Type:    "robot-secret",
				Payload: secret,
			},
		))
	}
	return dialOpts
}
