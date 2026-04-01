package event

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

type BufferSuite struct {
	suite.Suite
}

func TestBuffer(t *testing.T) {
	suite.Run(t, new(BufferSuite))
}

func (s *BufferSuite) TestAddAndRecent() {
	b := NewBuffer(5)

	b.Add(Event{Type: "a", Detail: "1"})
	b.Add(Event{Type: "b", Detail: "2"})
	b.Add(Event{Type: "c", Detail: "3"})

	got := b.Recent(10)
	s.Len(got, 3)
	s.Equal("3", got[0].Detail, "newest first")
	s.Equal("1", got[2].Detail, "oldest last")
}

func (s *BufferSuite) TestWrapAround() {
	b := NewBuffer(3)

	b.Add(Event{Detail: "1"})
	b.Add(Event{Detail: "2"})
	b.Add(Event{Detail: "3"})
	b.Add(Event{Detail: "4"}) // overwrites "1"

	got := b.Recent(10)
	s.Len(got, 3)
	s.Equal("4", got[0].Detail)
	s.Equal("3", got[1].Detail)
	s.Equal("2", got[2].Detail)
}

func (s *BufferSuite) TestRecentLimit() {
	b := NewBuffer(10)

	for i := range 10 {
		b.Add(Event{Detail: strconv.Itoa(i)})
	}

	got := b.Recent(3)
	s.Len(got, 3)
	s.Equal("9", got[0].Detail)
	s.Equal("8", got[1].Detail)
	s.Equal("7", got[2].Detail)
}

func (s *BufferSuite) TestEmpty() {
	b := NewBuffer(5)
	got := b.Recent(10)
	s.Empty(got)
}

func (s *BufferSuite) TestTimeAutoSet() {
	b := NewBuffer(5)
	b.Add(Event{Type: "test"})

	got := b.Recent(1)
	s.Require().Len(got, 1)
	s.False(got[0].Time.IsZero(), "time should be auto-set")
}
