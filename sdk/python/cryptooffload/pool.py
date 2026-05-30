"""gRPC 连接池，语义对齐 database/sql 与 Redis 连接池。"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Optional

import grpc


class PoolError(Exception):
    pass


class AcquireTimeout(PoolError):
    pass


@dataclass
class PoolConfig:
    address: str = "127.0.0.1:50051"
    min_idle: int = 2
    max_open: int = 16
    max_lifetime_sec: float = 30 * 60
    idle_timeout_sec: float = 5 * 60
    dial_timeout_sec: float = 5.0
    acquire_timeout_sec: float = 10.0


@dataclass
class _PooledConn:
    channel: grpc.Channel
    created_at: float
    last_used: float


class Conn:
    def __init__(self, pool: "Pool", channel: grpc.Channel) -> None:
        self._pool = pool
        self.channel = channel
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool._release(self.channel)


class Pool:
    def __init__(self, config: PoolConfig) -> None:
        if config.max_open < 1:
            raise ValueError("max_open must be >= 1")
        self._cfg = config
        self._idle: queue.Queue[_PooledConn] = queue.Queue()
        self._total = 0
        self._lock = threading.Lock()
        self._closed = False
        self._semaphore = threading.Semaphore(config.max_open)

    def warmup(self) -> None:
        while True:
            with self._lock:
                if self._closed or self._idle.qsize() >= self._cfg.min_idle:
                    break
                if self._total >= self._cfg.max_open:
                    break
            conn = self._dial()
            with self._lock:
                self._total += 1
            self._idle.put(
                _PooledConn(conn, time.monotonic(), time.monotonic())
            )

    def acquire(self) -> Conn:
        if not self._semaphore.acquire(timeout=self._cfg.acquire_timeout_sec):
            raise AcquireTimeout("acquire connection timeout")
        try:
            channel = self._get_or_dial()
            return Conn(self, channel)
        except Exception:
            self._semaphore.release()
            raise

    def close(self) -> None:
        with self._lock:
            self._closed = True
            while not self._idle.empty():
                entry = self._idle.get_nowait()
                entry.channel.close()
            self._total = 0

    def _get_or_dial(self) -> grpc.Channel:
        now = time.monotonic()
        while True:
            try:
                entry = self._idle.get_nowait()
            except queue.Empty:
                break
            if self._expired(entry, now):
                entry.channel.close()
                with self._lock:
                    self._total -= 1
                continue
            entry.last_used = now
            return entry.channel

        with self._lock:
            if self._total < self._cfg.max_open:
                self._total += 1
                need_dial = True
            else:
                need_dial = False
        if need_dial:
            return self._dial()
        # 等待其他连接归还
        entry = self._idle.get(timeout=self._cfg.acquire_timeout_sec)
        return entry.channel

    def _release(self, channel: grpc.Channel) -> None:
        with self._lock:
            if self._closed:
                channel.close()
                if self._total > 0:
                    self._total -= 1
                self._semaphore.release()
                return
        self._idle.put(_PooledConn(channel, time.monotonic(), time.monotonic()))
        self._semaphore.release()

    def _dial(self) -> grpc.Channel:
        return grpc.insecure_channel(
            self._cfg.address,
            options=(
                ("grpc.max_send_message_length", 1 * 1024 * 1024),
                ("grpc.max_receive_message_length", 1 * 1024 * 1024),
            ),
        )

    def _expired(self, entry: _PooledConn, now: float) -> bool:
        if now - entry.created_at > self._cfg.max_lifetime_sec:
            return True
        if now - entry.last_used > self._cfg.idle_timeout_sec:
            return True
        return False
