package dashboard

import (
	"context"
	"time"

	"wafsrv/internal/waf/ip"

	"github.com/vmkteam/zenrpc/v2"
)

// BlockService manages runtime blocking rules.
type BlockService struct {
	zenrpc.Service
	ipService *ip.Service
}

// NewBlockService creates a new BlockService.
func NewBlockService(ipService *ip.Service) *BlockService {
	return &BlockService{ipService: ipService}
}

// BlockEntry represents a blocked item in API responses.
type BlockEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Reason    string `json:"reason"`
	AddedAt   string `json:"addedAt"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Add adds a block rule.
//
//zenrpc:blockType Block type: "ip", "cidr", "country"
//zenrpc:value Value to block (IP address, CIDR, country code)
//zenrpc:reason Reason for blocking
//zenrpc:duration="" Optional duration (e.g. "1h", "30m"). Empty = permanent
//zenrpc:return bool
//zenrpc:400 Bad Request
func (s BlockService) Add(_ context.Context, blockType string, value string, reason string, duration string) (bool, error) {
	var dur time.Duration

	if duration != "" {
		var err error

		dur, err = time.ParseDuration(duration)
		if err != nil {
			return false, ErrBadRequest
		}
	}

	if err := s.ipService.AddBlock(blockType, value, reason, dur); err != nil {
		return false, ErrBadRequest
	}

	return true, nil
}

// Remove removes a block rule.
//
//zenrpc:blockType Block type: "ip", "cidr", "country"
//zenrpc:value Value to unblock
//zenrpc:return bool
//zenrpc:400 Bad Request
func (s BlockService) Remove(_ context.Context, blockType string, value string) (bool, error) {
	if err := s.ipService.RemoveBlock(blockType, value); err != nil {
		return false, ErrBadRequest
	}

	return true, nil
}

// List returns blocked items by type.
//
//zenrpc:blockType Block type: "ip", "cidr", "country"
//zenrpc:return []BlockEntry
//zenrpc:400 Bad Request
func (s BlockService) List(_ context.Context, blockType string) ([]BlockEntry, error) {
	entries := s.ipService.ListBlocks(blockType)
	if entries == nil {
		return nil, ErrBadRequest
	}

	result := make([]BlockEntry, 0, len(entries))
	for _, e := range entries {
		be := BlockEntry{
			Type:    blockType,
			Value:   e.Value,
			Reason:  e.Reason,
			AddedAt: e.AddedAt.Format(time.RFC3339),
		}

		if !e.ExpiresAt.IsZero() {
			be.ExpiresAt = e.ExpiresAt.Format(time.RFC3339)
		}

		result = append(result, be)
	}

	return result, nil
}
