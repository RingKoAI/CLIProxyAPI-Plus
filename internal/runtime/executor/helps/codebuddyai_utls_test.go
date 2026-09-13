package helps

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestNewCodeBuddyAIHTTPClientUsesContextRoundTripperWithoutProxy(t *testing.T) {
	marker := codeBuddyAIRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(marker))
	client := NewCodeBuddyAIHTTPClient(ctx, nil, nil, 0)
	if reflect.ValueOf(client.Transport).Pointer() != reflect.ValueOf(marker).Pointer() {
		t.Fatalf("transport = %T, want context transport", client.Transport)
	}
}

type codeBuddyAIRoundTripFunc func(*http.Request) (*http.Response, error)

func (f codeBuddyAIRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
