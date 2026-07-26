package client

import (
	"errors"

	"github.com/Saxy/Tellstone/internal/network"
)

var (
	// ErrRequestTooLarge is returned if the generated request exceeds the local stack buffer boundaries.
	ErrRequestTooLarge = network.ErrRequestTooLarge

	// ErrResponseBufferTooSmall is returned if the scratchpad buffer cannot hold the incoming server frame.
	ErrResponseBufferTooSmall = network.ErrResponseBufferTooSmall

	// ErrClientClosed is returned when operating on a closed client.
	ErrClientClosed = errors.New("client: closed")
)
