"""Unit tests for ether.gateway.network LHOST interface resolution."""

from unittest.mock import MagicMock, patch

from ether.gateway.network import clear_lhost_cache, get_lhost_info


def test_get_lhost_info_vpn_priority():
    clear_lhost_cache()
    mock_ip_out = """lo UNKNOWN 127.0.0.1/8 ::1/128
eth0 UP 192.168.1.100/24 fe80::1/64
tun0 UNKNOWN 10.10.14.33/23 fe80::2/64
"""
    with patch("ether.gateway.network.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_ip_out)
        ip, iface = get_lhost_info(ttl=0.0, force_refresh=True)
        assert ip == "10.10.14.33"
        assert iface == "tun0"


def test_get_lhost_info_regular_up():
    clear_lhost_cache()
    mock_ip_out = """lo UNKNOWN 127.0.0.1/8 ::1/128
eth0 UP 192.168.1.100/24 fe80::1/64
"""
    with patch("ether.gateway.network.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_ip_out)
        ip, iface = get_lhost_info(ttl=0.0, force_refresh=True)
        assert ip == "192.168.1.100"
        assert iface == "eth0"


def test_get_lhost_info_socket_fallback():
    clear_lhost_cache()
    with patch("ether.gateway.network.subprocess.run", side_effect=OSError("no ip command")):
        with patch("ether.gateway.network.socket.socket") as mock_socket:
            mock_s_inst = MagicMock()
            mock_s_inst.getsockname.return_value = ("192.168.1.50", 54321)
            mock_socket.return_value = mock_s_inst
            ip, iface = get_lhost_info(ttl=0.0, force_refresh=True)
            assert ip == "192.168.1.50"
            assert iface == "default"


def test_get_lhost_info_loopback_fallback():
    clear_lhost_cache()
    with patch("ether.gateway.network.subprocess.run", side_effect=OSError("no ip command")):
        with patch("ether.gateway.network.socket.socket", side_effect=OSError("no network")):
            ip, iface = get_lhost_info(ttl=0.0, force_refresh=True)
            assert ip == "127.0.0.1"
            assert iface == "lo"
