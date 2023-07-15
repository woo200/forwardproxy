class NetInterceptor:
    def setup(self, clientbound_sock, serverbound_sock) -> None:
        self.clientbound_sock = clientbound_sock
        self.serverbound_sock = serverbound_sock

        pass

    def handle_clientbound_chunk(self, chunk):
        return chunk

    def handle_serverbound_chunk(self, chunk):
        return chunk