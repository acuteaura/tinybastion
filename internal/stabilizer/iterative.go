package stabilizer

// NewIterative creates a new IterativeStabilizer with the provided threshold
func NewIterative[T comparable](threshold int) *IterativeStabilizer[T] {
	return &IterativeStabilizer[T]{data: make(map[T]int), threshold: threshold}
}

// IterativeStabilizer provides a way to track elements through multiple iterations of a process
type IterativeStabilizer[T comparable] struct {
	data      map[T]int
	threshold int
}

// Iterate matches provided elements to previous calls to Iterate and returns all elements that have been
// present in at least the number of runs configured as threshold.
func (s *IterativeStabilizer[T]) Iterate(elements map[T]struct{}) []T {
	newData := make(map[T]int)
	matches := make([]T, 0, len(elements))
	// seed all new elements to the map
	for k := range elements {
		if _, ok := s.data[k]; !ok {
			s.data[k] = 0
		}
	}
	for k, v := range s.data {
		if _, ok := elements[k]; !ok {
			// Element in previous run is not in this one
			// Drop out without adding the element back in
			continue
		}
		newData[k] = v + 1
		if newData[k] >= s.threshold {
			matches = append(matches, k)
		}
	}
	// this might seem wasteful, but it's still a memory for speed tradeoff
	s.data = newData
	return matches
}
