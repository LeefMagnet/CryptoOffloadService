// Package pool 提供 gRPC 连接池，设计思想对齐 database/sql 与 Redis 连接池：
//   - MinIdle：预热并保持最小空闲连接
//   - MaxOpen：限制最大并发连接，防止打爆服务端
//   - MaxLifetime / IdleTimeout：定期淘汰陈旧/空闲连接
//   - AcquireTimeout：池耗尽时阻塞等待的上限
package pool

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	ErrPoolClosed     = errors.New("connection pool closed")
	ErrAcquireTimeout = errors.New("acquire connection timeout")
	ErrInvalidMaxOpen = errors.New("max open connections must be >= 1")
)

// Config 连接池配置。
type Config struct {
	Address        string
	MinIdle        int
	MaxOpen        int
	MaxLifetime    time.Duration
	IdleTimeout    time.Duration
	DialTimeout    time.Duration
	AcquireTimeout time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.MinIdle < 0 {
		out.MinIdle = 0
	}
	if out.MaxOpen <= 0 {
		out.MaxOpen = 16
	}
	if out.MaxLifetime <= 0 {
		out.MaxLifetime = 30 * time.Minute
	}
	if out.IdleTimeout <= 0 {
		out.IdleTimeout = 5 * time.Minute
	}
	if out.DialTimeout <= 0 {
		out.DialTimeout = 5 * time.Second
	}
	if out.AcquireTimeout <= 0 {
		out.AcquireTimeout = 10 * time.Second
	}
	return out
}

type pooledConn struct {
	conn      *grpc.ClientConn
	createdAt time.Time
	lastUsed  time.Time
}

// Pool gRPC 连接池。
type Pool struct {
	cfg Config

	mu     sync.Mutex
	idle   []*pooledConn
	total  int
	closed bool

	sem chan struct{}
}

// New 创建连接池。
func New(cfg Config) (*Pool, error) {
	cfg = cfg.withDefaults()
	if cfg.MaxOpen < 1 {
		return nil, ErrInvalidMaxOpen
	}
	if cfg.MinIdle > cfg.MaxOpen {
		cfg.MinIdle = cfg.MaxOpen
	}
	return &Pool{
		cfg: cfg,
		sem: make(chan struct{}, cfg.MaxOpen),
	}, nil
}

// Warmup 预热到 MinIdle。
func (p *Pool) Warmup(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.idle) < p.cfg.MinIdle && p.total < p.cfg.MaxOpen {
		conn, err := p.dial(ctx)
		if err != nil {
			return err
		}
		p.total++
		p.idle = append(p.idle, &pooledConn{
			conn:      conn,
			createdAt: time.Now(),
			lastUsed:  time.Now(),
		})
	}
	return nil
}

// Acquire 借出连接；用完后必须调用 Conn.Release()。
func (p *Pool) Acquire(ctx context.Context) (*Conn, error) {
	if err := p.reserve(ctx); err != nil {
		return nil, err
	}
	conn, err := p.getOrDial(ctx)
	if err != nil {
		p.releaseSlot()
		return nil, err
	}
	return &Conn{pool: p, raw: conn}, nil
}

func (p *Pool) reserve(ctx context.Context) error {
	timer := time.NewTimer(p.cfg.AcquireTimeout)
	defer timer.Stop()
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrAcquireTimeout
	}
}

func (p *Pool) releaseSlot() {
	<-p.sem
}

func (p *Pool) getOrDial(ctx context.Context) (*grpc.ClientConn, error) {
	for {
		p.mu.Lock()
		if len(p.idle) > 0 {
			entry := p.idle[len(p.idle)-1]
			p.idle = p.idle[:len(p.idle)-1]
			p.mu.Unlock()
			if p.expired(entry) {
				entry.conn.Close()
				p.mu.Lock()
				p.total--
				p.mu.Unlock()
				continue
			}
			entry.lastUsed = time.Now()
			return entry.conn, nil
		}

		canDial := p.total < p.cfg.MaxOpen
		if canDial {
			p.total++
		}
		p.mu.Unlock()

		if !canDial {
			break
		}
		conn, err := p.dial(ctx)
		if err != nil {
			p.mu.Lock()
			p.total--
			p.mu.Unlock()
			return nil, err
		}
		return conn, nil
	}

	// 等待其他连接归还（简化：短暂自旋重试）
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return p.getOrDial(ctx)
	}
}

func (p *Pool) dial(ctx context.Context) (*grpc.ClientConn, error) {
	dctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	return grpc.DialContext(
		dctx,
		p.cfg.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

func (p *Pool) expired(entry *pooledConn) bool {
	now := time.Now()
	if now.Sub(entry.createdAt) > p.cfg.MaxLifetime {
		return true
	}
	if now.Sub(entry.lastUsed) > p.cfg.IdleTimeout {
		return true
	}
	return false
}

func (p *Pool) put(conn *grpc.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		if p.total > 0 {
			p.total--
		}
		p.releaseSlot()
		return
	}
	p.idle = append(p.idle, &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	})
	p.releaseSlot()
}

// Close 关闭连接池。
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	for _, entry := range p.idle {
		entry.conn.Close()
	}
	p.idle = nil
	p.total = 0
	return nil
}

// Conn 池化连接句柄。
type Conn struct {
	pool *Pool
	raw  *grpc.ClientConn
}

func (c *Conn) GRPC() *grpc.ClientConn { return c.raw }

// Release 归还连接到池。
func (c *Conn) Release() {
	if c == nil || c.raw == nil {
		return
	}
	c.pool.put(c.raw)
	c.raw = nil
}
