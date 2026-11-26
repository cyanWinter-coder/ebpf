package ringbuf

import (
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

// ringReader abstracts reading from a bpf ringbuf.
type ringReader struct {
	prod_pos, cons_pos *atomic.Uintptr

	// Local consumer position to support reading multiple messages from the ring
	// before committing.
	localCons uintptr

	// mask is the range of valid record start offsets, limited to the first half
	// of the double-mapped data pages.
	mask uintptr

	// data contains the double-mapped data pages of the ringbuf.
	data []byte

	// consumed is the total number of bytes advanced since the reader was
	// created. It is atomic because progress can be observed concurrently.
	consumed atomic.Uint64
}

// newRingReader creates a new ringReader with the given producer and consumer
// pointers and data pages.
func newRingReader(cons_ptr, prod_ptr *atomic.Uintptr, data []byte) *ringReader {
	return &ringReader{
		prod_pos:  prod_ptr,
		cons_pos:  cons_ptr,
		localCons: cons_ptr.Load(),
		// cap is always a power of two
		mask: uintptr(cap(data)/2 - 1),
		data: data,
	}
}

// To be able to wrap around data, data pages in ring buffers are mapped twice
// in a single contiguous virtual region. Therefore the returned usable size is
// half the size of the mmaped region.
func (rr *ringReader) size() int {
	return cap(rr.data) / 2
}

// consumedBytes reports the total number of ring bytes advanced since creation.
func (rr *ringReader) consumedBytes() uint64 {
	return rr.consumed.Load()
}

// The amount of data available to read in the ring buffer. Only tracks
// committed cursors.
func (rr *ringReader) available() int {
	return int(rr.prod_pos.Load() - rr.cons_pos.Load())
}

// commit sets the consumer position in shared kernel memory to the local
// consumer position.
func (rr *ringReader) commit() {
	rr.cons_pos.Store(rr.localCons)
}

// readSample returns the next sample from the ring buffer. data contains the
// sample's bytes, remain is the remaining number of bytes in the buffer after
// this sample.
//
// Returns [errEOR] if the end of the ring is reached, [errRecordBusy] if the
// producer is still updating the record, or an error wrapping
// [errInvalidRecord] if a record fails validation. Invalid records are skipped
// up to the producer position and their consumer position is committed.
//
// If data and err are nil, the sample was discarded by the producer.
//
// [ringReader.commit] must be called to advance the consumer position after
// every nil error, even if data is nil.
func (rr *ringReader) readSample() (data []byte, remain int, err error) {
	// Read kernel memory once per wakeup to avoid TOCTOU and unnecessary
	// synchronization.
	prod := rr.prod_pos.Load()
	cons := rr.localCons

	if remaining := prod - cons; remaining == 0 {
		return nil, 0, errEOR
	}

	headerSize := uintptr(sys.BPF_RINGBUF_HDR_SZ)
	if prod-cons < headerSize {
		return rr.skipInvalid(prod, fmt.Errorf(
			"%w: short record header: %w", errInvalidRecord, io.ErrUnexpectedEOF,
		))
	}

	// read the len field of the header atomically to ensure a happens before
	// relationship with the xchg in the kernel. Without this we may see len
	// without BPF_RINGBUF_BUSY_BIT before the written data is visible.
	// See https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/ringbuf.c#L484
	start := cons & rr.mask
	header := ringbufHeader{}
	header.Len = atomic.LoadUint32((*uint32)(unsafe.Pointer(&rr.data[start])))
	if header.isBusy() {
		// Sample has not been committed by the bpf program yet but should be
		// soon. The caller yields without advancing the consumer position.
		return nil, 0, errRecordBusy
	}

	dataLen := uintptr(header.dataLen())
	aligned := uintptr(header.dataLenAligned())
	frameSize := headerSize + aligned
	remaining := prod - cons

	if frameSize > uintptr(rr.size()) {
		return rr.skipInvalid(prod, fmt.Errorf(
			"%w: record length %d exceeds ring size %d",
			errInvalidRecord, frameSize, rr.size(),
		))
	}

	if remaining < frameSize {
		return rr.skipInvalid(prod, fmt.Errorf(
			"%w: record length %d exceeds %d available bytes: %w",
			errInvalidRecord, frameSize, remaining, io.ErrUnexpectedEOF,
		))
	}

	cons += headerSize
	start = cons & rr.mask
	if start+dataLen > uintptr(len(rr.data)) {
		return rr.skipInvalid(prod, fmt.Errorf(
			"%w: record payload [%d:%d] is outside mapped ring",
			errInvalidRecord, start, start+dataLen,
		))
	}

	cons += aligned

	rr.localCons = cons
	rr.consumed.Add(uint64(frameSize))

	remain = int(prod - cons)
	data = rr.data[start : start+dataLen]

	if header.isDiscard() {
		// Ringbuf space was reserved but then discarded. The consumer needs to
		// advance, but the sample data should not be returned.
		return nil, remain, nil
	}

	return data, remain, nil
}

// skipInvalid advances over an unparseable region. Record boundaries cannot be
// trusted once a header fails validation, so catch up to the producer position
// instead of trying to walk a bogus length.
func (rr *ringReader) skipInvalid(prod uintptr, err error) ([]byte, int, error) {
	rr.consumed.Add(uint64(prod - rr.localCons))
	rr.localCons = prod
	rr.commit()
	return nil, 0, err
}
