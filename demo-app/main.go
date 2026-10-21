// demo-app is a small HTTP service that prices orders.
// it is the application evidence-gate protects in CI (Github Actions)
//
//	POST /quote  {"items": [{"sku", "unit_price_cents", "quantity"}], "discount_code", "country"}
//	          -> {"subtotal_cents", "discount_cents", "vat_cents", "total_cents"}
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/vildande/evidence-gate/demo-app/pricing"
)

// limit request bodies, so a huge request cannot exhaust memory
const maxBodyBytes = 1 << 20 // 1 MiB

func main() {
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("demo-app listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, newMux()))
}

// routes, separate from main so tests can call them without a real server
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /quote", handleQuote) // other methods get 405 from the mux
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func handleQuote(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields() // a typo like "quantiy" is an error, not a silent 0

	var order pricing.Order
	if err := dec.Decode(&order); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	quote, err := pricing.Calculate(order)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, quote)
}

// validation errors are the client's fault (422), anything else is ours (500)
func statusFor(err error) int {
	for _, e := range []error{pricing.ErrNoItems, pricing.ErrInvalidItem, pricing.ErrUnknownDiscount, pricing.ErrUnknownCountry, pricing.ErrDiscountMinimum} {
		if errors.Is(err, e) {
			return http.StatusUnprocessableEntity
		}
	}
	return http.StatusInternalServerError
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// headers are already sent, so an encode error can only be logged
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}
