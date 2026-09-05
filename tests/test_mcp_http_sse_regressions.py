import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ida_pro_mcp import idalib_pool_server

mcp_mod = idalib_pool_server._mcp_mod
McpHttpRequestHandler = mcp_mod.McpHttpRequestHandler
McpServer = mcp_mod.McpServer


class _FakeServerBase:
    instances = []

    def __init__(self, server_address, request_handler, bind_and_activate=False):
        self.server_address = server_address
        self.request_handler = request_handler
        self.bind_and_activate = bind_and_activate
        self.allow_reuse_address = False
        self.bound = False
        self.activated = False
        self.closed = False
        self.served = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def server_bind(self):
        self.bound = True

    def server_activate(self):
        self.activated = True

    def server_close(self):
        self.closed = True

    def serve_forever(self):
        self.served = True


class _FakeThreadingHTTPServer(_FakeServerBase):
    instances = []


class _FakeHTTPServer(_FakeServerBase):
    instances = []


class McpServeTransportTests(unittest.TestCase):
    def setUp(self):
        _FakeThreadingHTTPServer.reset()
        _FakeHTTPServer.reset()

    def test_foreground_tcp_server_is_single_threaded_for_headless(self):
        # Headless idalib must run tool calls on the MAIN thread (see
        # sync.py / idalib_server.py). Foreground servers are single-threaded
        # by default so the HTTP handler runs on the thread that calls
        # serve_forever(). Regression test for the Windows/TCP deadlock where
        # ThreadingHTTPServer ran idalib_open off the main thread.
        server = McpServer("ida-pro-mcp")
        with patch.object(mcp_mod, "ThreadingHTTPServer", _FakeThreadingHTTPServer):
            with patch.object(mcp_mod, "HTTPServer", _FakeHTTPServer):
                server.serve(
                    host="127.0.0.1",
                    port=27144,
                    background=False,
                    request_handler=McpHttpRequestHandler,
                )

        self.assertEqual(len(_FakeThreadingHTTPServer.instances), 0)
        self.assertEqual(len(_FakeHTTPServer.instances), 1)
        self.assertTrue(_FakeHTTPServer.instances[0].bound)
        self.assertTrue(_FakeHTTPServer.instances[0].activated)
        self.assertTrue(_FakeHTTPServer.instances[0].served)

    def test_background_tcp_server_is_threaded(self):
        # Background / GUI-plugin servers handle requests on worker threads;
        # the in-IDA main loop dispatches @idasync via execute_sync there.
        server = McpServer("ida-pro-mcp")
        with patch.object(mcp_mod, "ThreadingHTTPServer", _FakeThreadingHTTPServer):
            with patch.object(mcp_mod, "HTTPServer", _FakeHTTPServer):
                server.serve(
                    host="127.0.0.1",
                    port=27145,
                    background=True,
                    request_handler=McpHttpRequestHandler,
                )

        self.assertEqual(len(_FakeThreadingHTTPServer.instances), 1)
        self.assertEqual(len(_FakeHTTPServer.instances), 0)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].bound)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].activated)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].served)

    def test_foreground_tcp_server_can_request_threaded_for_sse(self):
        # SSE needs a long-lived GET stream plus concurrent POST handling;
        # opt in explicitly with threaded=True even in foreground mode.
        server = McpServer("ida-pro-mcp")
        with patch.object(mcp_mod, "ThreadingHTTPServer", _FakeThreadingHTTPServer):
            with patch.object(mcp_mod, "HTTPServer", _FakeHTTPServer):
                server.serve(
                    host="127.0.0.1",
                    port=27146,
                    background=False,
                    threaded=True,
                    request_handler=McpHttpRequestHandler,
                )

        self.assertEqual(len(_FakeThreadingHTTPServer.instances), 1)
        self.assertEqual(len(_FakeHTTPServer.instances), 0)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].bound)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].activated)
        self.assertTrue(_FakeThreadingHTTPServer.instances[0].served)


class McpProtocolNotificationTests(unittest.TestCase):
    def test_initialized_notification_is_accepted(self):
        server = McpServer("ida-pro-mcp")
        request = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": None,
        }

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            response = server.registry.dispatch(request)

        self.assertIsNone(response)
        self.assertNotIn(
            "Method 'notifications/initialized' not found",
            stdout.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
