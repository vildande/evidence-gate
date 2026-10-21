package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vildande/evidence-gate/demo-app/pricing"
)

// TestQuote - checks that a valid order returns 200 and the calculated quote.
// TestQuoteBadRequests - checks status codes and error bodies for invalid requests.
// TestHealthz - checks that the health endpoint returns 200.
// TestStatusForUnknownError - checks that a non-validation error maps to 500.

// send a request to the app and return the recorded response
func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	return rec
}

func TestQuote(t *testing.T) {
	body := `{"items": [{"sku": "A", "unit_price_cents": 5000, "quantity": 1}], "discount_code": "WELCOME10", "country": "DE"}`
	rec := do(t, http.MethodPost, "/quote", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}

	var got pricing.Quote
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := pricing.Quote{SubtotalCents: 5000, DiscountCents: 500, VATCents: 855, TotalCents: 5355}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestQuoteBadRequests(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		body      string
		status    int
		wantError string // part of the "error" field, "" when there is no JSON body
	}{
		{"malformed JSON", http.MethodPost, `{"items": [`, http.StatusBadRequest, "invalid JSON"},
		{"unknown field", http.MethodPost, `{"country": "DE", "quantiy": 1}`, http.StatusBadRequest, "unknown field"},
		{"no items", http.MethodPost, `{"country": "DE", "items": []}`, http.StatusUnprocessableEntity, "no items"},
		{"unknown country", http.MethodPost, `{"country": "XX", "items": [{"sku": "A", "unit_price_cents": 1, "quantity": 1}]}`, http.StatusUnprocessableEntity, "unknown country"},
		{"wrong method", http.MethodGet, "", http.StatusMethodNotAllowed, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, tt.method, "/quote", tt.body)
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, tt.status, rec.Body)
			}
			if tt.wantError == "" {
				return
			}

			var resp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(resp.Error, tt.wantError) {
				t.Errorf("error %q, want it to contain %q", resp.Error, tt.wantError)
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	if rec := do(t, http.MethodGet, "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
}

func TestStatusForUnknownError(t *testing.T) {
	if got := statusFor(errors.New("disk on fire")); got != http.StatusInternalServerError {
		t.Errorf("got %d, want 500", got)
	}
}
