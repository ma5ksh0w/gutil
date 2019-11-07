 package bhx

import (
	"crypto/rand"
	"testing"
)

func bubHash256sort(a []Hash256) []Hash256 {
	l := len(a)
	for i := 0; i < l; i++ {
		for j := l - 1; j >= 0; j-- {
			if a[i].ToBigInt().Cmp(a[j].ToBigInt()) > 0 {
				a[i], a[j] = a[j], a[i]
			}
		}
	}

	return a
}

func BenchmarkQsort(b *testing.B) {
	a := []Hash256{}
	for i := 0; i < 20; i++ {
		var h Hash256
		rand.Read(h[:])
		a = append(a, h)
	}

	for i := 0; i < b.N; i++ {
		b := a[:]
		b = SortHash256(b)
	}
}

func BenchmarkBsort(b *testing.B) {
	a := []Hash256{}
	for i := 0; i < 20; i++ {
		var h Hash256
		rand.Read(h[:])
		a = append(a, h)
	}

	for i := 0; i < b.N; i++ {
		b := a[:]
		b = bubHash256sort(b)
	}
}
