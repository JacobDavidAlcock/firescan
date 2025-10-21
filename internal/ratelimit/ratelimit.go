package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter controls the rate of operations
type Limiter struct {
	rate       int           // requests per second
	interval   time.Duration // time between requests
	lastAction time.Time
	mu         sync.Mutex
}

// NewLimiter creates a new rate limiter
// rate: maximum requests per second (0 = unlimited)
func NewLimiter(requestsPerSecond int) *Limiter {
	if requestsPerSecond <= 0 {
		// No rate limiting
		return &Limiter{
			rate:     0,
			interval: 0,
		}
	}

	return &Limiter{
		rate:       requestsPerSecond,
		interval:   time.Second / time.Duration(requestsPerSecond),
		lastAction: time.Now(),
	}
}

// Wait blocks until the rate limiter allows the next operation
func (l *Limiter) Wait(ctx context.Context) error {
	if l.rate == 0 {
		// No rate limiting
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastAction)

	if elapsed < l.interval {
		sleepDuration := l.interval - elapsed

		// Check if context is already cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Sleep with context cancellation support
		timer := time.NewTimer(sleepDuration)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Sleep completed
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	l.lastAction = time.Now()
	return nil
}

// WaitN waits for permission to perform n operations
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	for i := 0; i < n; i++ {
		if err := l.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

// GetRate returns the current rate limit (requests per second)
func (l *Limiter) GetRate() int {
	return l.rate
}

// SetRate updates the rate limit
func (l *Limiter) SetRate(requestsPerSecond int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if requestsPerSecond <= 0 {
		l.rate = 0
		l.interval = 0
		return
	}

	l.rate = requestsPerSecond
	l.interval = time.Second / time.Duration(requestsPerSecond)
}
