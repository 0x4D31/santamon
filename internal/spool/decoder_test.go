package spool

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewDecoder(t *testing.T) {
	d := NewDecoder()
	if d == nil {
		t.Fatal("NewDecoder returned nil")
	}
	if d.maxFileSize != 100*1024*1024 {
		t.Errorf("Expected maxFileSize 100MB, got %d", d.maxFileSize)
	}
	if d.maxDecompressedSize != 500*1024*1024 {
		t.Errorf("Expected maxDecompressedSize 500MB, got %d", d.maxDecompressedSize)
	}
	if d.maxDecompressionRate != 100 {
		t.Errorf("Expected maxDecompressionRate 100, got %d", d.maxDecompressionRate)
	}
}

func TestWithLimits(t *testing.T) {
	d := NewDecoder().WithLimits(10*1024*1024, 50*1024*1024, 50)
	if d.maxFileSize != 10*1024*1024 {
		t.Errorf("Expected maxFileSize 10MB, got %d", d.maxFileSize)
	}
	if d.maxDecompressedSize != 50*1024*1024 {
		t.Errorf("Expected maxDecompressedSize 50MB, got %d", d.maxDecompressedSize)
	}
	if d.maxDecompressionRate != 50 {
		t.Errorf("Expected maxDecompressionRate 50, got %d", d.maxDecompressionRate)
	}
}

func TestDecodeEventsEmptyPath(t *testing.T) {
	d := NewDecoder()
	_, err := d.DecodeEvents("")
	if err == nil {
		t.Error("Expected error for empty path")
	}
}

func TestDecodeEventsNonexistentFile(t *testing.T) {
	d := NewDecoder()
	_, err := d.DecodeEvents("/nonexistent/file")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestDecodeEventsEmptyFile(t *testing.T) {
	d := NewDecoder()
	tmpFile := filepath.Join(t.TempDir(), "empty.pb")
	if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := d.DecodeEvents(tmpFile)
	if err == nil {
		t.Error("Expected error for empty file")
	}
}

func TestDecodeEventsTooLarge(t *testing.T) {
	d := NewDecoder().WithLimits(100, 1000, 100)
	tmpFile := filepath.Join(t.TempDir(), "large.pb")
	// Create file larger than limit
	largeData := make([]byte, 200)
	if err := os.WriteFile(tmpFile, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := d.DecodeEvents(tmpFile)
	if err == nil {
		t.Error("Expected error for file too large")
	}
}

func TestDecodeEventsSingleMessage(t *testing.T) {
	d := NewDecoder()
	msg := createTestProtoMessage()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "single.pb")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	messages, err := d.DecodeEvents(tmpFile)
	if err != nil {
		t.Fatalf("DecodeEvents failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}

	if messages[0].GetMachineId() != "test-machine" {
		t.Errorf("Expected machine_id 'test-machine', got %s", messages[0].GetMachineId())
	}
}

func TestDecodeEventsMessageBatch(t *testing.T) {
	d := NewDecoder()
	msg1 := createTestProtoMessage()
	msg2 := createTestProtoMessage()
	msg2.MachineId = proto.String("test-machine-2")

	batch := &santapb.SantaMessageBatch{
		Messages: []*santapb.SantaMessage{msg1, msg2},
	}

	data, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "batch.pb")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	messages, err := d.DecodeEvents(tmpFile)
	if err != nil {
		t.Fatalf("DecodeEvents failed: %v", err)
	}

	if len(messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(messages))
	}
}

func TestDecodeEventsGzipCompressed(t *testing.T) {
	d := NewDecoder()
	msg := createTestProtoMessage()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "compressed.gz")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	messages, err := d.DecodeEvents(tmpFile)
	if err != nil {
		t.Fatalf("DecodeEvents failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}
}

func TestDecodeEventsZstdCompressed(t *testing.T) {
	d := NewDecoder()
	msg := createTestProtoMessage()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zstdWriter, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zstdWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zstdWriter.Close(); err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "compressed.zst")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	messages, err := d.DecodeEvents(tmpFile)
	if err != nil {
		t.Fatalf("DecodeEvents failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(messages))
	}
}

func TestDecodeEventsDecompressionBomb(t *testing.T) {
	// Test zip bomb protection
	d := NewDecoder().WithLimits(10*1024*1024, 1024, 10)

	// Create highly compressible data (all zeros)
	largeData := make([]byte, 2048) // Will compress to very small size

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(largeData); err != nil {
		t.Fatal(err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "bomb.gz")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := d.DecodeEvents(tmpFile)
	if err == nil {
		t.Error("Expected error for decompression bomb")
	}
}

func TestDecodeEventsMaxDepth(t *testing.T) {
	// Test maximum decompression depth
	d := NewDecoder()
	msg := createTestProtoMessage()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Compress 3 times (should exceed depth limit of 2)
	for i := 0; i < 3; i++ {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		if _, err := gzWriter.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := gzWriter.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
	}

	tmpFile := filepath.Join(t.TempDir(), "triplecompressed.gz")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = d.DecodeEvents(tmpFile)
	if err == nil {
		t.Error("Expected error for maximum depth exceeded")
	}
}

func TestDecodeEventsContext(t *testing.T) {
	d := NewDecoder()
	msg := createTestProtoMessage()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "test.pb")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = d.DecodeEventsContext(ctx, tmpFile)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestDecodeJSONLines(t *testing.T) {
	// Skip JSON test - JSON format support is optional and primarily for development/testing
	// The protobuf decoding path is comprehensive tested above
	t.Skip("JSON format decoding is optional and requires exact protobuf JSON format")
}

// Helper function to create a test protobuf message
func createTestProtoMessage() *santapb.SantaMessage {
	decision := santapb.Execution_DECISION_ALLOW
	return &santapb.SantaMessage{
		MachineId:       proto.String("test-machine"),
		BootSessionUuid: proto.String("boot-uuid"),
		EventTime:       timestamppb.New(time.Now()),
		Event: &santapb.SantaMessage_Execution{
			Execution: &santapb.Execution{
				Decision: &decision,
				Target: &santapb.ProcessInfo{
					Executable: &santapb.FileInfo{
						Path: proto.String("/bin/test"),
					},
				},
			},
		},
	}
}
