"""
Unit tests for PortScanner module.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import socket

# Asegurar importación de herramientas
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.network.port_scanner import PortScanner, parse_ports, ScanResult, COMMON_PORTS


class TestPortScanner(unittest.TestCase):

    def test_parse_ports_single(self):
        ports = parse_ports("80")
        self.assertEqual(ports, [80])

    def test_parse_ports_list(self):
        ports = parse_ports("80, 443, 22")
        self.assertEqual(ports, [22, 80, 443])

    def test_parse_ports_range(self):
        ports = parse_ports("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

    def test_parse_ports_common(self):
        ports = parse_ports("common")
        self.assertEqual(ports, sorted(list(COMMON_PORTS.keys())))

    def test_parse_ports_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("invalid")
        with self.assertRaises(ValueError):
            parse_ports("70000")
        with self.assertRaises(ValueError):
            parse_ports("100-50")

    @patch("socket.gethostbyname")
    def test_scanner_init_resolution(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "192.168.1.1"
        scanner = PortScanner("test.local", timeout=0.5)
        self.assertEqual(scanner.ip, "192.168.1.1")
        self.assertEqual(scanner.timeout, 0.5)

    @patch("socket.gethostbyname")
    def test_scanner_init_failure(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror
        with self.assertRaises(ValueError):
            PortScanner("unresolvable.invalid")

    @patch("socket.gethostbyname")
    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket_cls, mock_gethostbyname):
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_sock_inst = MagicMock()
        mock_sock_inst.connect_ex.return_value = 0
        mock_socket_cls.return_value.__enter__.return_value = mock_sock_inst

        scanner = PortScanner("127.0.0.1")
        result = scanner.scan_port(80)

        self.assertEqual(result.port, 80)
        self.assertEqual(result.status, "OPEN")
        self.assertEqual(result.service, "HTTP")

    @patch("socket.gethostbyname")
    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket_cls, mock_gethostbyname):
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_sock_inst = MagicMock()
        mock_sock_inst.connect_ex.return_value = 111  # Connection refused
        mock_socket_cls.return_value.__enter__.return_value = mock_sock_inst

        scanner = PortScanner("127.0.0.1")
        result = scanner.scan_port(9999)

        self.assertEqual(result.port, 9999)
        self.assertEqual(result.status, "CLOSED")


if __name__ == "__main__":
    unittest.main()
