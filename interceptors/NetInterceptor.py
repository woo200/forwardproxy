class NetInterceptor:
    def setup(self, clientbound_sock, serverbound_sock, client_name) -> None:
        self.clientbound_sock = clientbound_sock
        self.serverbound_sock = serverbound_sock
        self.client_name = client_name

        pass

    def handle_clientbound_chunk(self, chunk):
        return chunk

    def handle_serverbound_chunk(self, chunk):
        return chunk