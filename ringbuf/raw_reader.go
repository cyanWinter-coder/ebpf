package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

// RawReader reads raw samples submitted to a BPF ringbuf.
//
// RawReader exposes samples as slices backed by shared ring memory. Access to
// that memory is scoped to a [Lease] obtained via [RawReader.WithLease].
// Returned samples remain valid until the next call to [Lease.Commit] or
// until the session ends.
//
// RawReader must not be used concurrently by multiple goroutines, except that
// [RawReader.Close] and [RawReader.Flush] may be called from another goroutine
// to interrupt a blocked read.
//
// Use [Reader] instead for a thread-safe alternative.
type RawReader struct {
	poller poller

	ring       eventRing
	deadline   time.Time
	bufferSize int
	drainErr   error

	inflight, closed atomic.Bool

	// closeMu serializes ring teardown with progress calls that read mapped
	// ring memory. Read calls are excluded by inflight instead.
	closeMu sync.RWMutex

	stats readerStats

	// The following fields are only accessed by the goroutine that owns an
	// inflight Lease.
	nextSequence uint64
	lastSkipped  uint64
	lastSequence uint64
	lastLost     uint64
}

// ReaderStats contains counters and progress information for a [Reader] or
// [RawReader].
type ReaderStats struct {
	// Sequence is the sequence number most recently assigned to a record.
	Sequence uint64

	// ReadCount is the number of valid samples returned to callers.
	ReadCount uint64

	// ReadBytes is the total number of valid sample bytes returned.
	ReadBytes uint64

	// DiscardedCount is the number of samples discarded by the BPF producer.
	DiscardedCount uint64

	// SkippedCount is the number of invalid or incomplete ring records that
	// were skipped.
	SkippedCount uint64

	// LostCount is the total sequence gap attributed to skipped records.
	LostCount uint64

	// ConsumedBytes is the number of ring bytes advanced past since the
	// reader was created, including headers, alignment padding and skipped
	// bytes.
	ConsumedBytes uint64
}

// Stats is an alias for [ReaderStats].
type Stats = ReaderStats

type readerStats struct {
	sequence       atomic.Uint64
	readCount      atomic.Uint64
	readBytes      atomic.Uint64
	discardedCount atomic.Uint64
	skippedCount   atomic.Uint64
	lostCount      atomic.Uint64
}

func (s *readerStats) snapshot() ReaderStats {
	return ReaderStats{
		Sequence:       s.sequence.Load(),
		ReadCount:      s.readCount.Load(),
		ReadBytes:      s.readBytes.Load(),
		DiscardedCount: s.discardedCount.Load(),
		SkippedCount:   s.skippedCount.Load(),
		LostCount:      s.lostCount.Load(),
	}
}

// Stats returns a snapshot of reader counters and progress.
func (rr *RawReader) Stats() ReaderStats {
	rr.closeMu.RLock()
	defer rr.closeMu.RUnlock()

	stats := rr.stats.snapshot()
	if progress, ok := rr.ring.(interface{ consumedBytes() uint64 }); ok {
		stats.ConsumedBytes = progress.consumedBytes()
	}
	return stats
}

// Stats returns a snapshot of reader counters and progress.
func (r *Reader) Stats() ReaderStats {
	return r.raw.Stats()
}

var errConcurrent = errors.New("concurrent use of RawReader")

// enter marks the start of an in-flight lease. It returns an error if the
// reader is already in-flight or closed. Every successful call to enter must be
// paired with a call to [RawReader.leave].
func (rr *RawReader) enter() error {
	if !rr.inflight.CompareAndSwap(false, true) {
		return errConcurrent
	}

	if rr.closed.Load() {
		rr.leave()
		return fmt.Errorf("ringbuf: %w", ErrClosed)
	}

	return nil
}

// leave resets the reader's in-flight state.
func (rr *RawReader) leave() {
	rr.inflight.Store(false)
}

// NewRawReader creates a new raw BPF ringbuf reader. The given Map must be of
// type [ebpf.RingBuf] or [ebpf.WindowsRingBuf].
func NewRawReader(m *ebpf.Map) (*RawReader, error) {
	if m.Type() != ebpf.RingBuf && m.Type() != ebpf.WindowsRingBuf {
		return nil, fmt.Errorf("invalid Map type: %s", m.Type())
	}

	maxEntries := int(m.MaxEntries())
	if maxEntries == 0 || !internal.IsPow(maxEntries) {
		return nil, fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := newPoller(m.FD())
	if err != nil {
		return nil, err
	}

	ring, err := newRingBufEventRing(m.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return nil, fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	return &RawReader{
		poller:     poller,
		ring:       ring,
		bufferSize: ring.size(),
	}, nil
}

// WithLease calls fn with exclusive access to rr.
//
// The provided Lease is only valid for the duration of fn. The callback may
// call [Lease.ReadSample] multiple times before [Lease.Commit] to batch
// consumer position updates.
//
// The callback must not call [RawReader.Close] on the same reader.
func (rr *RawReader) WithLease(fn func(Lease) error) error {
	if err := rr.enter(); err != nil {
		return err
	}
	defer rr.leave()

	return fn(Lease{rr: rr})
}

// Close frees resources used by the reader, unblocking any pending reads.
//
// When a read returns [os.ErrClosed], there are no more samples left in the
// ring.
func (rr *RawReader) Close() error {
	if !rr.closed.CompareAndSwap(false, true) {
		return nil
	}

	if err := rr.poller.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("close poller: %w", err)
	}

	for rr.inflight.Load() {
		runtime.Gosched()
	}

	rr.closeMu.Lock()
	defer rr.closeMu.Unlock()

	return rr.ring.close()
}

// SetDeadline controls how long reads will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (rr *RawReader) SetDeadline(t time.Time) {
	rr.deadline = t
}

// Lease provides exclusive access to a [RawReader] for the duration of a
// [RawReader.WithLease] callback.
//
// A Lease is only valid during that callback and must not be used outside of
// the scope of [RawReader.WithLease].
type Lease struct {
	rr *RawReader
}

// ReadSample blocks and reads the next sample from the BPF ringbuf. The
// returned data aliases shared ring memory and is only valid until the next
// call to [Lease.Commit] or until the surrounding [RawReader.WithLease]
// callback returns.
//
// If the returned data is nil, the sample was discarded by the producer.
//
// If a nil error is returned, the reader's internal consumer position has
// advanced and [Lease.Commit] should be called, e.g. when batching reads.
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and exceeded. Either
// no samples were produced, or the producer used BPF_RB_NO_WAKEUP when
// submitting samples and reading should continue.
func (s Lease) ReadSample() (data []byte, remain int, err error) {
	rr := s.rr

	for {
		if rr.closed.Load() {
			return nil, 0, fmt.Errorf("ringbuf read: %w", ErrClosed)
		}

		// On Windows, the wait handle is only set when the reader is created, so we
		// miss any wakeups that happened before. Do an opportunistic read to get
		// any pending samples.
		data, remain, err := rr.ring.readSample()
		if err == nil {
			if data == nil {
				rr.stats.discardedCount.Add(1)
			} else {
				rr.stats.readCount.Add(1)
				rr.stats.readBytes.Add(uint64(len(data)))
				rr.advanceSequence()
			}
			return data, remain, nil
		}

		switch {
		case errors.Is(err, errRecordBusy):
			// The producer is still updating the record. Yield instead of
			// blocking in the poller, but stay responsive to Close.
			if rr.closed.Load() {
				return nil, 0, fmt.Errorf("ringbuf read: %w", ErrClosed)
			}
			if !rr.deadline.IsZero() && !time.Now().Before(rr.deadline) {
				return nil, 0, fmt.Errorf("ringbuf read: %w", os.ErrDeadlineExceeded)
			}
			runtime.Gosched()
			continue

		case errors.Is(err, errInvalidRecord):
			rr.stats.skippedCount.Add(1)
			if rr.closed.Load() {
				return nil, 0, fmt.Errorf("ringbuf read: %w", ErrClosed)
			}
			continue

		case errors.Is(err, errEOR):
			// Fall through to waiting below.

		default:
			return nil, 0, err
		}

		if err := rr.drainErr; err != nil {
			rr.drainErr = nil
			return nil, 0, err
		}

		err = rr.poller.Wait(rr.deadline)
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
			rr.drainErr = err
			continue
		}

		if err != nil {
			return nil, 0, err
		}
	}
}

// Commit pushes the reader's internal consumer position to shared kernel
// memory.
func (s Lease) Commit() {
	s.rr.ring.commit()
}

// Sequence returns the sequence number assigned to the sample returned by the
// most recent successful [Lease.ReadSample] call.
func (s Lease) Sequence() uint64 {
	return s.rr.lastSequence
}

// LostSamples returns the sequence gap attributed to skipped records before
// the sample returned by the most recent successful [Lease.ReadSample] call.
func (s Lease) LostSamples() uint64 {
	return s.rr.lastLost
}

func (rr *RawReader) advanceSequence() {
	skipped := rr.stats.skippedCount.Load()
	lost := skipped - rr.lastSkipped
	rr.lastSkipped = skipped

	if rr.nextSequence == 0 {
		rr.nextSequence = 1
	}
	rr.nextSequence += lost

	rr.lastSequence = rr.nextSequence
	rr.nextSequence++
	rr.lastLost = lost

	rr.stats.sequence.Store(rr.lastSequence)
	rr.stats.lostCount.Add(lost)
}

// BufferSize returns the size in bytes of the ring buffer's data portion.
func (rr *RawReader) BufferSize() int {
	return rr.bufferSize
}

// Flush unblocks any pending reads. Successive reads will return any and all
// samples left in the ring (e.g. previously submitted with BPF_RB_NO_WAKEUP).
// When a read returns [ErrFlushed], there are no more samples left in the ring.
func (rr *RawReader) Flush() error {
	return rr.poller.Flush()
}

// AvailableBytes returns the amount of bytes submitted by the producer that are
// not yet consumed by the reader, typically for monitoring purposes.
//
// Only tracks cursors committed to shared memory, ignoring the reader's local
// consumer position. If the reader is batching commits, this may return an
// inflated value.
func (rr *RawReader) AvailableBytes() int {
	rr.closeMu.RLock()
	defer rr.closeMu.RUnlock()

	if rr.closed.Load() {
		return 0
	}
	return rr.ring.available()
}
