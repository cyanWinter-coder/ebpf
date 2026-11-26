package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")

	errRecordBusy    = errors.New("ringbuf record is not complete")
	errInvalidRecord = errors.New("invalid ringbuf record")
)

// poller abstracts platform-specific event notification.
type poller interface {
	Wait(deadline time.Time) error
	Flush() error
	Close() error
}

// eventRing abstracts platform-specific ring buffer memory access.
type eventRing interface {
	size() int
	available() int
	readSample() (data []byte, remain int, err error)
	commit()
	close() error
}

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len uint32
	_   uint32 // pg_off, only used by kernel internals
}

const ringbufHeaderSize = int(unsafe.Sizeof(ringbufHeader{}))

func (rh *ringbufHeader) isBusy() bool {
	return rh.Len&sys.BPF_RINGBUF_BUSY_BIT != 0
}

func (rh *ringbufHeader) isDiscard() bool {
	return rh.Len&sys.BPF_RINGBUF_DISCARD_BIT != 0
}

func (rh *ringbufHeader) dataLen() int {
	return int(rh.Len & ^uint32(sys.BPF_RINGBUF_BUSY_BIT|sys.BPF_RINGBUF_DISCARD_BIT))
}

// dataLenAligned returns the length of the sample data as specified in the
// header, aligned to an 8 byte boundary.
func (rh *ringbufHeader) dataLenAligned() int {
	return int(internal.Align(rh.dataLen(), 8))
}

type Record struct {
	RawSample []byte

	// The minimum number of bytes remaining in the ring buffer after this Record has been read.
	Remaining int

	// Sequence is the reader-local sequence number of this record. The first
	// record has sequence one, and sequence numbers are contiguous unless one
	// or more invalid records were skipped.
	Sequence uint64

	// LostSamples is the number of records skipped between the previous
	// returned record and this one.
	LostSamples uint64
}

// Reader reads [Record]s submitted to a BPF ringbuf.
//
// It is safe for concurrent use by multiple goroutines.
type Reader struct {
	mu  sync.Mutex
	raw *RawReader
}

// NewReader creates a new BPF ringbuf reader. The given Map must be of type
// [ebpf.RingBuf] or [ebpf.WindowsRingBuf].
//
// The returned Reader is safe for concurrent use by multiple goroutines.
func NewReader(m *ebpf.Map) (*Reader, error) {
	raw, err := NewRawReader(m)
	if err != nil {
		return nil, fmt.Errorf("create reader: %w", err)
	}
	return &Reader{raw: raw}, nil
}

// Close frees resources used by the reader, unblocking any pending reads.
//
// When a read returns [os.ErrClosed], there are no more samples left in the
// ring.
func (r *Reader) Close() error {
	return r.raw.Close()
}

// SetDeadline controls how long reads will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (r *Reader) SetDeadline(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.raw.SetDeadline(t)
}

// Read the next record from the BPF ringbuf.
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and exceeded. Either
// no samples were produced, or the producer used BPF_RB_NO_WAKEUP when
// submitting samples and reading should continue.
//
// See [Reader.ReadInto] for a more efficient version of this method.
func (r *Reader) Read() (Record, error) {
	var rec Record
	err := r.ReadInto(&rec)
	return rec, err
}

// ReadInto is like [Reader.Read], but allows reusing Record and associated
// buffers.
func (r *Reader) ReadInto(rec *Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.raw.enter(); err != nil {
		return err
	}
	defer r.raw.leave()

	lease := Lease{rr: r.raw}

	for {
		data, remain, err := lease.ReadSample()
		if err != nil {
			return err
		}

		if data == nil {
			// Consumer needs to advance even if the producer discarded the sample,
			// since space was reserved for it in the ring.
			lease.Commit()
			continue
		}

		rec.Sequence = lease.Sequence()
		rec.LostSamples = lease.LostSamples()

		if cap(rec.RawSample) < len(data) {
			rec.RawSample = make([]byte, len(data))
		} else {
			rec.RawSample = rec.RawSample[:len(data)]
		}

		copy(rec.RawSample, data)
		rec.Remaining = remain

		// Advance the reader, invalidating the sample data.
		lease.Commit()

		return nil
	}
}

// BufferSize returns the size in bytes of the ring buffer's data portion.
func (r *Reader) BufferSize() int {
	return r.raw.BufferSize()
}

// Flush unblocks any pending reads. Successive reads will return any and all
// samples left in the ring (e.g. previously submitted with BPF_RB_NO_WAKEUP).
// When a read returns [ErrFlushed], there are no more samples left in the ring.
func (r *Reader) Flush() error {
	return r.raw.Flush()
}

// AvailableBytes returns the amount of bytes submitted by the producer that are
// not yet consumed by the reader, typically for monitoring purposes.
func (r *Reader) AvailableBytes() int {
	return r.raw.AvailableBytes()
}
