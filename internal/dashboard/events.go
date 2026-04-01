package dashboard

import (
	"context"

	"wafsrv/internal/waf/event"

	"github.com/vmkteam/zenrpc/v2"
)

// EventsService provides access to recent security events.
type EventsService struct {
	zenrpc.Service
	recorder *event.Recorder
}

// NewEventsService creates a new EventsService.
func NewEventsService(recorder *event.Recorder) *EventsService {
	return &EventsService{recorder: recorder}
}

// EventEntry is an event in API responses.
type EventEntry struct {
	Time     string `json:"time"`
	Type     string `json:"type"`
	ClientIP string `json:"clientIp"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
}

// Recent returns the last N security events.
//
//zenrpc:limit=50 Maximum number of events to return
//zenrpc:return []EventEntry
func (s EventsService) Recent(_ context.Context, limit int) []EventEntry {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	items := s.recorder.RecentEvents(limit)
	result := make([]EventEntry, len(items))

	for i, e := range items {
		result[i] = EventEntry{
			Time:     e.Time.Format("15:04:05"),
			Type:     e.Type,
			ClientIP: e.ClientIP,
			Path:     e.Path,
			Detail:   e.Detail,
		}
	}

	return result
}
