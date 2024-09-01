import socket

class UdpSock:
    def __init__(self):
        self._sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __del__(self):
        # Ensure the socket resource is closed and doesn't leak
        if self.is_good():
            self._sd.close()

    def __call__(self):
        return self._sd

    def is_good(self):
        return self._sd is not None
