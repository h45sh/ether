"""Unit tests for StreamTarpitGuard and inline tarpit mitigation in executor.py."""

from ether.core.executor import StreamTarpitGuard


def test_tarpit_guard_normal_throughput():
    guard = StreamTarpitGuard(window_seconds=15.0, min_bytes_per_sec=10.0)
    t0 = 1000.0

    # Send 100 bytes every second for 16 seconds
    for i in range(16):
        is_tarpit, reason = guard.check_chunk(100, f"data_{i}".encode(), t0 + i)
        assert not is_tarpit
        assert reason == ""


def test_tarpit_guard_slow_drip_detection():
    guard = StreamTarpitGuard(window_seconds=15.0, min_bytes_per_sec=10.0)
    t0 = 1000.0

    # Send 1 byte every 4 seconds
    # After 16 seconds, total bytes = 5 bytes over 16s = ~0.3 B/s < 10 B/s
    triggered = False
    for i in range(5):
        t = t0 + (i * 4.0)
        is_tarpit, reason = guard.check_chunk(1, b"x", t)
        if is_tarpit:
            triggered = True
            assert "Delay-tarpit detected" in reason
            break

    assert triggered


def test_tarpit_guard_infinite_banner_loop():
    guard = StreamTarpitGuard(window_seconds=15.0, min_bytes_per_sec=10.0)
    t0 = 1000.0
    identical_chunk = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"

    # Send identical chunk every 2 seconds for 16 seconds with NO findings
    triggered = False
    for i in range(9):
        t = t0 + (i * 2.0)
        is_tarpit, reason = guard.check_chunk(len(identical_chunk), identical_chunk, t)
        if is_tarpit:
            triggered = True
            assert "Banner loop detected" in reason
            break

    assert triggered


def test_tarpit_guard_banner_with_progress_not_blocked():
    guard = StreamTarpitGuard(window_seconds=15.0, min_bytes_per_sec=10.0)
    t0 = 1000.0
    identical_chunk = b"Scanning port... Found active service.\r\n"

    # Send identical chunk every 2 seconds, but record finding every 5 seconds
    triggered = False
    for i in range(9):
        t = t0 + (i * 2.0)
        if i % 2 == 0:
            guard.record_finding(t)
        is_tarpit, reason = guard.check_chunk(len(identical_chunk), identical_chunk, t)
        if is_tarpit:
            triggered = True
            break

    assert not triggered
