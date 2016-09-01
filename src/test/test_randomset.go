package main

import (
	"fmt"

	"requestor/randomset"
)

func order_to_number(order []int) int {
	base := order[0] * 2
	if order[1] < order[2] {
		return base + 1
	} else {
		return base
	}
}

func main() {
	seed := make([]byte, 1)
	seed[0] = 43

	results := make([]int, 6)
	i := 0
	for ; i < 1000000; i++ {
		identity := fmt.Sprintf("%d", i)
		subset, err := randomset.RandomSubset(
			seed, []byte(identity), 3, 3)
		if err == nil {
			index := order_to_number(subset)
			results[index]++
		}
	}

	for j := 0; j < 6; j++ {
		fmt.Printf("%d: %f\n", j,
			(float64(results[j])-float64(i)/6.0)/(float64(i)))
	}
}
