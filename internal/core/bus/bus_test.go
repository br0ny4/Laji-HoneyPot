package bus

import (
	"sync"
	"testing"
	"time"
)

func TestPublishSubscribe(t *testing.T) {
	b := New()
	var mu sync.Mutex
	var received []string

	b.Subscribe("alert", func(e Event) {
		mu.Lock()
		received = append(received, string(e.Payload))
		mu.Unlock()
	})

	err := b.Publish("alert", []byte("intrusion detected"))
	if err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // 等待异步分发

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0] != "intrusion detected" {
		t.Errorf("unexpected received: %v", received)
	}
}

func TestPublishNoHandler(t *testing.T) {
	b := New()
	err := b.Publish("nonexistent", []byte("data"))
	if err == nil {
		t.Error("expected error for topic with no handlers")
	}
}

func TestTopics(t *testing.T) {
	b := New()
	b.Subscribe("topic-a", func(e Event) {})
	b.Subscribe("topic-b", func(e Event) {})

	topics := b.Topics()
	if len(topics) != 2 {
		t.Errorf("expected 2 topics, got %d", len(topics))
	}
}
