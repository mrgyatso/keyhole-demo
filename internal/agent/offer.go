package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/version"
)

// FetchOffer asks the relay what a temporary install with this token would
// be, so the endpoint user is shown the MSP's own terms rather than whatever
// the technician typed on the command line. It consumes no token use and
// returns no credential.
//
// The token is held for the one request and, like enrolment, is never written
// to disk or logged.
func FetchOffer(ctx context.Context, relayURL, token string, client *http.Client) (*proto.TempOffer, error) {
	relay, err := relayBase(relayURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("offer: no enrollment token")
	}
	b, err := json.Marshal(proto.TempOfferRequest{Token: strings.TrimSpace(token), OS: runtime.GOOS})
	if err != nil {
		return nil, fmt.Errorf("offer: encode request: %w", err)
	}
	defer wipe(b) // holds the token
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, relay+proto.TempOfferPath, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("offer: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "keyhole-agent/"+version.Version)
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("offer: POST %s: %w", relay+proto.TempOfferPath, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponse))
	if err != nil {
		return nil, fmt.Errorf("offer: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var he proto.HTTPError
		if json.Unmarshal(data, &he) == nil && he.Error.Code != "" {
			return nil, fmt.Errorf("offer: relay refused (HTTP %d): %w", resp.StatusCode, &he.Error)
		}
		return nil, fmt.Errorf("offer: relay returned HTTP %d: %s", resp.StatusCode, snippet(data))
	}
	var o proto.TempOffer
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("offer: decode response: %w", err)
	}
	switch {
	case !o.Ephemeral:
		return nil, errors.New("offer: the relay did not offer a temporary installation")
	case o.Client == "":
		return nil, errors.New("offer: the relay named no client")
	case o.MaxDuration <= 0:
		return nil, errors.New("offer: the relay set no maximum duration")
	}
	return &o, nil
}
