// Package pricing calculates the price of an order: subtotal, discount, VAT and total.
// all amounts are integer cents, so there are no floating point rounding errors.
package pricing

import (
	"errors"
	"fmt"
	"strings"
)

// validation errors, so callers can tell bad input from other failures
var (
	ErrNoItems         = errors.New("order has no items")
	ErrInvalidItem     = errors.New("invalid item")
	ErrUnknownDiscount = errors.New("unknown discount code")
	ErrUnknownCountry  = errors.New("unknown country")
)

// one order line
type Item struct {
	SKU            string `json:"sku"`
	UnitPriceCents int64  `json:"unit_price_cents"`
	Quantity       int64  `json:"quantity"`
}

type Order struct {
	Items        []Item `json:"items"`
	DiscountCode string `json:"discount_code"` // optional
	Country      string `json:"country"`       // ISO code, e.g. "DE"
}

// calculated price of an order
type Quote struct {
	SubtotalCents int64 `json:"subtotal_cents"`
	DiscountCents int64 `json:"discount_cents"`
	VATCents      int64 `json:"vat_cents"`
	TotalCents    int64 `json:"total_cents"`
}

// VAT rate in percent per country
var vatRates = map[string]int64{
	"DE": 19,
	"FR": 20,
	"IT": 22,
	"NL": 21,
}

// a discount is either a percentage or a fixed amount off the subtotal
type discount struct {
	percent int64
	cents   int64
}

var discounts = map[string]discount{
	"WELCOME10": {percent: 10},
	"FLAT5":     {cents: 500},
}

// calculate the quote. the discount is applied before VAT
func Calculate(o Order) (Quote, error) {
	if len(o.Items) == 0 {
		return Quote{}, ErrNoItems
	}

	rate, ok := vatRates[strings.ToUpper(o.Country)]
	if !ok {
		return Quote{}, fmt.Errorf("%w: %q", ErrUnknownCountry, o.Country)
	}

	var q Quote
	for i, it := range o.Items {
		if it.SKU == "" || it.Quantity <= 0 || it.UnitPriceCents < 0 {
			return Quote{}, fmt.Errorf("%w: item %d needs a sku, quantity > 0 and price >= 0", ErrInvalidItem, i)
		}
		q.SubtotalCents += it.UnitPriceCents * it.Quantity
	}

	if o.DiscountCode != "" {
		d, ok := discounts[strings.ToUpper(o.DiscountCode)]
		if !ok {
			return Quote{}, fmt.Errorf("%w: %q", ErrUnknownDiscount, o.DiscountCode)
		}
		q.DiscountCents = percentOf(q.SubtotalCents, d.percent) + d.cents
		q.DiscountCents = min(q.DiscountCents, q.SubtotalCents) // never below zero
	}

	net := q.SubtotalCents - q.DiscountCents
	q.VATCents = percentOf(net, rate)
	q.TotalCents = net + q.VATCents
	return q, nil
}

// percent of an amount, rounded half up to whole cents (amount >= 0)
func percentOf(cents, percent int64) int64 {
	return (cents*percent + 50) / 100
}
