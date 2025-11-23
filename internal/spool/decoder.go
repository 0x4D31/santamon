package spool

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

// Decoder handles decoding Santa protobuf spool files (primary) with an optional
// JSON fallback used for development and testing fixtures.
type Decoder struct {
	json                 protojson.UnmarshalOptions
	maxFileSize          int64 // Maximum file size in bytes
	maxDecompressedSize  int64 // Maximum decompressed size to prevent zip bombs
	maxDecompressionRate int   // Maximum compression ratio (decompressed/compressed)
}

// NewDecoder creates a new decoder with default limits.
func NewDecoder() *Decoder {
	return &Decoder{
		json: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
		maxFileSize:          100 * 1024 * 1024, // 100MB
		maxDecompressedSize:  500 * 1024 * 1024, // 500MB decompressed
		maxDecompressionRate: 100,               // Max 100:1 compression ratio
	}
}

// WithLimits creates a decoder with custom size limits.
func (d *Decoder) WithLimits(maxFileSize, maxDecompressedSize int64, maxRate int) *Decoder {
	d.maxFileSize = maxFileSize
	d.maxDecompressedSize = maxDecompressedSize
	d.maxDecompressionRate = maxRate
	return d
}

// DecodeEvents decodes multiple Santa events from a spool file.
func (d *Decoder) DecodeEvents(path string) ([]*santapb.SantaMessage, error) {
	return d.DecodeEventsContext(context.Background(), path)
}

// DecodeEventsContext decodes multiple Santa events with context support.
func (d *Decoder) DecodeEventsContext(ctx context.Context, path string) ([]*santapb.SantaMessage, error) {
	if path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Check context before expensive operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	if info.Size() > d.maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max %d)", info.Size(), d.maxFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Check context after file read
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if msgs, err := d.decodeProtobuf(ctx, data, 0); err == nil {
		return msgs, nil
	}

	if d.isJSON(data) {
		return d.decodeJSONLines(data)
	}

	return nil, fmt.Errorf("unsupported spool format: %s", path)
}

func (d *Decoder) decodeProtobuf(ctx context.Context, data []byte, depth int) ([]*santapb.SantaMessage, error) {
	if len(data) == 0 {
		return nil, errors.New("no data")
	}

	// Prevent infinite decompression recursion
	if depth > 2 {
		return nil, errors.New("maximum decompression depth exceeded")
	}

	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(data) >= 4 {
		magic := binary.LittleEndian.Uint32(data[:4])
		switch {
		case magic == streamBatcherMagic:
			if os.Getenv("SANTAMON_DEBUG") == "1" {
				log.Printf("decoder: detected stream batch")
			}
			return parseStreamBatch(ctx, data)
		case magic == zstdMagic:
			if os.Getenv("SANTAMON_DEBUG") == "1" {
				log.Printf("decoder: detected zstd batch (depth %d)", depth)
			}
			plain, err := d.decompressZSTD(data)
			if err != nil {
				return nil, err
			}
			return d.decodeProtobuf(ctx, plain, depth+1)
		case magic&0xffff == gzipMagic:
			if os.Getenv("SANTAMON_DEBUG") == "1" {
				log.Printf("decoder: detected gzip batch (depth %d)", depth)
			}
			plain, err := d.decompressGZIP(data)
			if err != nil {
				return nil, err
			}
			return d.decodeProtobuf(ctx, plain, depth+1)
		}
	}

	var logBatch santapb.LogBatch
	if err := proto.Unmarshal(data, &logBatch); err == nil {
		if os.Getenv("SANTAMON_DEBUG") == "1" {
			log.Printf("decoder: telemetry.LogBatch parsed, records=%d", len(logBatch.GetRecords()))
		}
		if len(logBatch.GetRecords()) > 0 {
			if msgs, err := d.messagesFromLogBatch(&logBatch); err == nil && len(msgs) > 0 {
				return msgs, nil
			}
			// Fall through to alternate parsing if empty or error
		}
	}

	if msgs, err := parseBinaryLogBatch(data); err == nil {
		if os.Getenv("SANTAMON_DEBUG") == "1" {
			log.Printf("decoder: binary LogBatch parsed, messages=%d", len(msgs))
		}
		if len(msgs) > 0 {
			return msgs, nil
		}
	}

	var batch santapb.SantaMessageBatch
	if err := proto.Unmarshal(data, &batch); err == nil {
		if os.Getenv("SANTAMON_DEBUG") == "1" {
			log.Printf("decoder: SantaMessageBatch parsed, messages=%d", len(batch.GetMessages()))
		}
		if len(batch.GetMessages()) > 0 {
			return cloneMessages(batch.GetMessages()), nil
		}
	}

	var single santapb.SantaMessage
	if err := proto.Unmarshal(data, &single); err == nil {
		if os.Getenv("SANTAMON_DEBUG") == "1" {
			hasEvent := single.GetEvent() != nil
			log.Printf("decoder: SantaMessage parsed, hasEvent=%v", hasEvent)
		}
		if single.GetEvent() != nil {
			return []*santapb.SantaMessage{proto.Clone(&single).(*santapb.SantaMessage)}, nil
		}
	}

	return nil, errors.New("not protobuf Santa telemetry")
}

func (d *Decoder) messagesFromLogBatch(batch *santapb.LogBatch) ([]*santapb.SantaMessage, error) {
	var out []*santapb.SantaMessage

	for _, record := range batch.GetRecords() {
		if record == nil {
			continue
		}
		// Directly unmarshal the Any.Value into SantaMessage (ignore type_url package name)
		var single santapb.SantaMessage
		if err := proto.Unmarshal(record.GetValue(), &single); err == nil {
			out = append(out, proto.Clone(&single).(*santapb.SantaMessage))
			continue
		}

		// Try SantaMessageBatch in the Any.Value
		var batchMsg santapb.SantaMessageBatch
		if err := proto.Unmarshal(record.GetValue(), &batchMsg); err == nil && len(batchMsg.GetMessages()) > 0 {
			out = append(out, cloneMessages(batchMsg.GetMessages())...)
			continue
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("log batch contained no Santa messages")
	}

	return out, nil
}

func cloneMessages(msgs []*santapb.SantaMessage) []*santapb.SantaMessage {
	out := make([]*santapb.SantaMessage, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		out = append(out, proto.Clone(msg).(*santapb.SantaMessage))
	}
	return out
}

func (d *Decoder) decodeJSONLines(data []byte) ([]*santapb.SantaMessage, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) > 100000 {
		return nil, fmt.Errorf("too many lines in JSON file: %d (max 100000)", len(lines))
	}

	var messages []*santapb.SantaMessage
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 2*1024*1024 {
			return nil, fmt.Errorf("line %d too large (max 2MB)", i+1)
		}

		var msg santapb.SantaMessage
		if err := d.json.Unmarshal([]byte(line), &msg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON line %d: %w", i+1, err)
		}
		if msg.GetEvent() == nil {
			continue
		}
		messages = append(messages, proto.Clone(&msg).(*santapb.SantaMessage))
	}

	if len(messages) == 0 {
		return nil, fmt.Errorf("no JSON telemetry records found")
	}

	return messages, nil
}

func (d *Decoder) isJSON(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	first := data[0]
	return first == '{' || first == '['
}

const (
	// streamBatcherMagic is the 4-byte magic number "SNT!" (0x534E5421 big-endian, 0x21544E53 little-endian)
	// used to identify Santa stream batcher format files
	streamBatcherMagic = 0x21544E53

	// zstdMagic is the 4-byte Zstandard magic number (0x28B52FFD big-endian, 0xFD2FB528 little-endian)
	// as defined in RFC 8878
	zstdMagic = 0xfd2fb528

	// gzipMagic is the 2-byte gzip magic number (0x1F8B)
	// as defined in RFC 1952
	gzipMagic = 0x8b1f
)

func parseBinaryLogBatch(data []byte) ([]*santapb.SantaMessage, error) {
	messages := make([]*santapb.SantaMessage, 0)

	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]

		switch typ {
		case protowire.BytesType:
			val, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			data = data[m:]

			if num != 1 {
				continue
			}

			anyMsg := &anypb.Any{}
			if err := proto.Unmarshal(val, anyMsg); err != nil {
				return nil, fmt.Errorf("failed to unmarshal Any record: %w", err)
			}
			// Unmarshal Any.Value directly to avoid type_url package mismatch.
			var msg santapb.SantaMessage
			if err := proto.Unmarshal(anyMsg.GetValue(), &msg); err != nil {
				return nil, fmt.Errorf("failed to unmarshal SantaMessage value: %w", err)
			}
			messages = append(messages, proto.Clone(&msg).(*santapb.SantaMessage))

		default:
			m := protowire.ConsumeFieldValue(num, typ, data)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}

	return messages, nil
}

func parseStreamBatch(ctx context.Context, data []byte) ([]*santapb.SantaMessage, error) {
	reader := bytes.NewReader(data)
	messages := make([]*santapb.SantaMessage, 0)

	// Limit number of messages to prevent memory exhaustion
	const maxMessages = 100000

	for {
		// Check context periodically
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var magic uint32
		if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read stream magic: %w", err)
		}
		if magic != streamBatcherMagic {
			return nil, fmt.Errorf("invalid stream magic: 0x%x", magic)
		}

		var expectedHash uint64
		if err := binary.Read(reader, binary.LittleEndian, &expectedHash); err != nil {
			return nil, fmt.Errorf("failed to read stream hash: %w", err)
		}

		length, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read stream length: %w", err)
		}

		// Validate message length to prevent excessive memory allocation
		if length == 0 {
			return nil, fmt.Errorf("invalid zero-length message in stream")
		}
		if length > 10*1024*1024 { // Max 10MB per message
			return nil, fmt.Errorf("stream message too large: %d bytes", length)
		}

		msgBuf := make([]byte, length)
		if _, err := io.ReadFull(reader, msgBuf); err != nil {
			return nil, fmt.Errorf("failed to read stream message: %w", err)
		}

		if expectedHash != 0 {
			if sum := xxhash.Sum64(msgBuf); sum != expectedHash {
				return nil, fmt.Errorf("stream hash mismatch: expected %x got %x", expectedHash, sum)
			}
		}

		var msg santapb.SantaMessage
		if err := proto.Unmarshal(msgBuf, &msg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SantaMessage: %w", err)
		}

		if msg.GetEvent() != nil {
			messages = append(messages, proto.Clone(&msg).(*santapb.SantaMessage))
		}

		// Check message count limit
		if len(messages) > maxMessages {
			return nil, fmt.Errorf("too many messages in stream: %d (max %d)", len(messages), maxMessages)
		}
	}

	if len(messages) == 0 {
		return nil, errors.New("stream batch contained no valid messages")
	}

	return messages, nil
}

func (d *Decoder) decompressZSTD(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	dec, err := zstd.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to init zstd reader: %w", err)
	}
	defer dec.Close()

	// Use limited reader to prevent zip bombs
	limitedReader := io.LimitReader(dec, d.maxDecompressedSize)
	plain, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress zstd stream: %w", err)
	}

	// Check decompression ratio
	if len(plain) >= int(d.maxDecompressedSize) {
		return nil, fmt.Errorf("decompressed size limit exceeded (max %d bytes)", d.maxDecompressedSize)
	}
	if len(data) > 0 && len(plain)/len(data) > d.maxDecompressionRate {
		return nil, fmt.Errorf("decompression ratio too high: %d:1 (max %d:1)",
			len(plain)/len(data), d.maxDecompressionRate)
	}

	return plain, nil
}

func (d *Decoder) decompressGZIP(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to init gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// Use limited reader to prevent zip bombs
	limitedReader := io.LimitReader(gr, d.maxDecompressedSize)
	plain, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip stream: %w", err)
	}

	// Check decompression ratio
	if len(plain) >= int(d.maxDecompressedSize) {
		return nil, fmt.Errorf("decompressed size limit exceeded (max %d bytes)", d.maxDecompressedSize)
	}
	if len(data) > 0 && len(plain)/len(data) > d.maxDecompressionRate {
		return nil, fmt.Errorf("decompression ratio too high: %d:1 (max %d:1)",
			len(plain)/len(data), d.maxDecompressionRate)
	}

	return plain, nil
}
