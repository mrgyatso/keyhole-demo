package store_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/store"
)

// An ephemeral token enrolls exactly one device even when every enrollment
// races for it: the check and the use are one immediate transaction.
func TestEphemeralTokenIsSingleUseUnderConcurrency(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	secret := addToken(t, st, "acme", ephemeral(time.Hour))

	const racers = 16
	var (
		wg    sync.WaitGroup
		won   atomic.Int32
		start = make(chan struct{})
		errs  = make(chan error, racers)
	)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := st.EnrollDevice(ctx, store.EnrollParams{
				Secret: secret,
				Device: newDevice(fmt.Sprintf("U-race-%d", i), fmt.Sprintf("m-race-%d", i)),
				Now:    time.Now(),
			})
			switch {
			case err == nil:
				won.Add(1)
			case !errors.Is(err, model.ErrExhausted):
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a racing enrollment failed with %v, want %v", err, model.ErrExhausted)
	}
	if n := won.Load(); n != 1 {
		t.Fatalf("%d devices enrolled with a one-use token", n)
	}
}
