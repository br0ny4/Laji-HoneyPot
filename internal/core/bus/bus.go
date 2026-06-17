package bus

import (
	"fmt"
	"sync"
)

// Event 表示一条事件
type Event struct {
	Topic   string
	Payload []byte
}

// Handler 事件处理函数
type Handler func(Event)

// Bus 事件总线，插件间异步通信。
// 采用本地 channel 实现，零外部依赖。
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
}

// New 创建事件总线
func New() *Bus {
	return &Bus{
		handlers: make(map[string][]Handler),
	}
}

// Subscribe 订阅主题
func (b *Bus) Subscribe(topic string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[topic] = append(b.handlers[topic], handler)
}

// Publish 向主题发布事件（异步，非阻塞）
func (b *Bus) Publish(topic string, payload []byte) error {
	b.mu.RLock()
	handlers := b.handlers[topic]
	b.mu.RUnlock()

	if len(handlers) == 0 {
		return fmt.Errorf("no handlers for topic: %s", topic)
	}

	evt := Event{Topic: topic, Payload: payload}
	for _, h := range handlers {
		go h(evt) // 异步分发
	}
	return nil
}

// PublishSync 同步发布事件
func (b *Bus) PublishSync(topic string, payload []byte) error {
	b.mu.RLock()
	handlers := b.handlers[topic]
	b.mu.RUnlock()

	if len(handlers) == 0 {
		return fmt.Errorf("no handlers for topic: %s", topic)
	}

	evt := Event{Topic: topic, Payload: payload}
	for _, h := range handlers {
		h(evt)
	}
	return nil
}

// Topics 返回所有已注册主题
func (b *Bus) Topics() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	topics := make([]string, 0, len(b.handlers))
	for t := range b.handlers {
		topics = append(topics, t)
	}
	return topics
}
