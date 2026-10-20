package pricing

import (
	"errors"
	"testing"
)

// TestCalculate — checks subtotal, discount, VAT and total for valid orders.
// TestCalculateErrors — checks that invalid orders return the matching validation error.

func TestCalculate(t *testing.T) {
	tests := []struct {
		name  string
		order Order
		want  Quote
	}{
		{
			name:  "single item",
			order: Order{Country: "DE", Items: []Item{{SKU: "A", UnitPriceCents: 1000, Quantity: 1}}},
			want:  Quote{SubtotalCents: 1000, VATCents: 190, TotalCents: 1190},
		},
		{
			name: "several items and quantities",
			order: Order{Country: "FR", Items: []Item{
				{SKU: "A", UnitPriceCents: 250, Quantity: 4},
				{SKU: "B", UnitPriceCents: 1999, Quantity: 1},
			}},
			want: Quote{SubtotalCents: 2999, VATCents: 600, TotalCents: 3599},
		},
		{
			name:  "percent discount before VAT",
			order: Order{Country: "DE", DiscountCode: "WELCOME10", Items: []Item{{SKU: "A", UnitPriceCents: 5000, Quantity: 1}}},
			want:  Quote{SubtotalCents: 5000, DiscountCents: 500, VATCents: 855, TotalCents: 5355},
		},
		{
			name:  "fixed discount",
			order: Order{Country: "NL", DiscountCode: "FLAT5", Items: []Item{{SKU: "A", UnitPriceCents: 2000, Quantity: 1}}},
			want:  Quote{SubtotalCents: 2000, DiscountCents: 500, VATCents: 315, TotalCents: 1815},
		},
		{
			name:  "fixed discount larger than subtotal",
			order: Order{Country: "DE", DiscountCode: "FLAT5", Items: []Item{{SKU: "A", UnitPriceCents: 300, Quantity: 1}}},
			want:  Quote{SubtotalCents: 300, DiscountCents: 300, VATCents: 0, TotalCents: 0},
		},
		{
			name:  "codes and countries are case-insensitive",
			order: Order{Country: "it", DiscountCode: "welcome10", Items: []Item{{SKU: "A", UnitPriceCents: 1000, Quantity: 1}}},
			want:  Quote{SubtotalCents: 1000, DiscountCents: 100, VATCents: 198, TotalCents: 1098},
		},
		{
			name:  "VAT rounds half up",
			order: Order{Country: "DE", Items: []Item{{SKU: "A", UnitPriceCents: 50, Quantity: 1}}}, // 19% of 50 = 9.5
			want:  Quote{SubtotalCents: 50, VATCents: 10, TotalCents: 60},
		},
		{
			name:  "free item",
			order: Order{Country: "DE", Items: []Item{{SKU: "GIFT", UnitPriceCents: 0, Quantity: 1}}},
			want:  Quote{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Calculate(tt.order)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCalculateErrors(t *testing.T) {
	item := Item{SKU: "A", UnitPriceCents: 100, Quantity: 1}
	tests := []struct {
		name  string
		order Order
		want  error
	}{
		{"no items", Order{Country: "DE"}, ErrNoItems},
		{"unknown country", Order{Country: "XX", Items: []Item{item}}, ErrUnknownCountry},
		{"unknown discount", Order{Country: "DE", DiscountCode: "FREE", Items: []Item{item}}, ErrUnknownDiscount},
		{"missing sku", Order{Country: "DE", Items: []Item{{UnitPriceCents: 100, Quantity: 1}}}, ErrInvalidItem},
		{"zero quantity", Order{Country: "DE", Items: []Item{{SKU: "A", UnitPriceCents: 100}}}, ErrInvalidItem},
		{"negative price", Order{Country: "DE", Items: []Item{{SKU: "A", UnitPriceCents: -1, Quantity: 1}}}, ErrInvalidItem},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Calculate(tt.order)
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}
