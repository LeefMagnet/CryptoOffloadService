package com.cryptooffload.sdk;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * gRPC 连接池，语义对齐 JDBC / Lettuce Redis 连接池。
 */
public final class GrpcConnectionPool implements AutoCloseable {
    private final String address;
    private final int maxOpen;
    private final long maxLifetimeMs;
    private final long idleTimeoutMs;
    private final long acquireTimeoutMs;

    private final Semaphore semaphore;
    private final Deque<PooledChannel> idle = new ArrayDeque<>();
    private final Object lock = new Object();
    private int total;
    private boolean closed;

    public GrpcConnectionPool(PoolConfig config) {
        this.address = config.address();
        this.maxOpen = Math.max(1, config.maxOpen());
        this.maxLifetimeMs = config.maxLifetime().toMillis();
        this.idleTimeoutMs = config.idleTimeout().toMillis();
        this.acquireTimeoutMs = config.acquireTimeout().toMillis();
        this.semaphore = new Semaphore(maxOpen);
    }

    public PooledConn acquire() throws InterruptedException {
        if (!semaphore.tryAcquire(acquireTimeoutMs, TimeUnit.MILLISECONDS)) {
            throw new PoolException("acquire connection timeout");
        }
        ManagedChannel channel = borrowOrDial();
        return new PooledConn(this, channel);
    }

    private ManagedChannel borrowOrDial() {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            while (!idle.isEmpty()) {
                PooledChannel entry = idle.removeLast();
                if (isExpired(entry, now)) {
                    entry.channel.shutdownNow();
                    total--;
                    continue;
                }
                entry.lastUsedMs = now;
                return entry.channel;
            }
            if (total < maxOpen) {
                total++;
            } else {
                throw new PoolException("pool exhausted");
            }
        }
        return ManagedChannelBuilder.forTarget(address)
                .usePlaintext()
                .build();
    }

    void release(ManagedChannel channel) {
        synchronized (lock) {
            if (closed) {
                channel.shutdownNow();
                if (total > 0) {
                    total--;
                }
                semaphore.release();
                return;
            }
            long now = System.currentTimeMillis();
            idle.addLast(new PooledChannel(channel, now, now));
        }
        semaphore.release();
    }

    private boolean isExpired(PooledChannel entry, long now) {
        return now - entry.createdAtMs > maxLifetimeMs
                || now - entry.lastUsedMs > idleTimeoutMs;
    }

    @Override
    public void close() {
        synchronized (lock) {
            closed = true;
            for (PooledChannel entry : idle) {
                entry.channel.shutdownNow();
            }
            idle.clear();
            total = 0;
        }
    }

    public record PoolConfig(
            String address,
            int minIdle,
            int maxOpen,
            Duration maxLifetime,
            Duration idleTimeout,
            Duration acquireTimeout
    ) {
        public static PoolConfig defaults() {
            return new PoolConfig(
                    "127.0.0.1:50051",
                    2,
                    16,
                    Duration.ofMinutes(30),
                    Duration.ofMinutes(5),
                    Duration.ofSeconds(10)
            );
        }
    }

    private static final class PooledChannel {
        final ManagedChannel channel;
        final long createdAtMs;
        long lastUsedMs;

        PooledChannel(ManagedChannel channel, long createdAtMs, long lastUsedMs) {
            this.channel = channel;
            this.createdAtMs = createdAtMs;
            this.lastUsedMs = lastUsedMs;
        }
    }

    public static final class PooledConn implements AutoCloseable {
        private final GrpcConnectionPool pool;
        private ManagedChannel channel;

        PooledConn(GrpcConnectionPool pool, ManagedChannel channel) {
            this.pool = pool;
            this.channel = channel;
        }

        public ManagedChannel channel() {
            return channel;
        }

        @Override
        public void close() {
            if (channel != null) {
                pool.release(channel);
                channel = null;
            }
        }
    }

    public static class PoolException extends RuntimeException {
        public PoolException(String message) {
            super(message);
        }
    }
}
