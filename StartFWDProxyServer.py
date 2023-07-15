import sockslib
import socket
import threading
import select
import boto3
import random
import json

import LaunchNewSOCKS5

from loguru import logger

ec2 = boto3.resource('ec2',region_name='us-west-1')

class ForwardServer:
    def __init__(self, fwd_host, fwd_port, proxy=None, host='127.0.0.1', port=1234) -> None:
        self.proxy_addr = (proxy['ip'], proxy['port']) if proxy else None
        self.proxy_authentication = [sockslib.NoAuth(),
                                     sockslib.UserPassAuth(proxy['username'], proxy['password'])] if proxy else None

        self.bind_addr = (host, port)
        self.fwd_addr  = (fwd_host, fwd_port)
        
        self.server_socket = None

        self.client_threads = []
        self.client_signals = []
    
    def __safe_shutdown(self, sock):
        try:
            sock.shutdown()
        except:
            pass

        try:
            sock.close()
        except:
            pass

    def __forward(self, sock1, sock2, stop_event, client_name):
        sock1.setblocking(False)

        while True:
            try:
                ready = select.select([sock1], [], [], 10)
                if ready[0]:
                    data = sock1.recv(4096)
                    if not data:
                        break
                    sock2.sendall(data)
                if stop_event.is_set():
                    break
            except socket.error as e:
                stop_event.set()
                break
            except Exception as e:
                logger.error(f"[{client_name}] Forwarding stopped: {e}")
                stop_event.set()
                break

        self.__safe_shutdown(sock1)
        self.__safe_shutdown(sock2)

        stop_event.set()

    def __handle_client(self, conn, addr):
        if self.proxy_addr is None:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            client_sock = sockslib.SocksSocket()
            client_sock.set_proxy(self.proxy_addr, 
                                sockslib.Socks.SOCKS5, 
                                self.proxy_authentication)
        client_name = f"{addr[0]}:{addr[1]}"
        
        logger.info(f"[{client_name}] Connecting to {self.fwd_addr[0]}:{self.fwd_addr[1]}")
        client_sock.settimeout(10)

        try:
            client_sock.connect(self.fwd_addr)
        except TimeoutError:
            logger.info(f"[{client_name}] Connection timed out.")

            self.__safe_shutdown(client_sock)
            self.__safe_shutdown(conn)

            return
        except Exception as e:
            logger.error(f"[{client_name}] Connection failed: {e}")

            self.__safe_shutdown(client_sock)
            self.__safe_shutdown(conn)

            return
        
        logger.info(f"[{client_name}] Connected to {self.fwd_addr[0]}:{self.fwd_addr[1]}")

        stop_event = threading.Event()
        client_thread = threading.Thread(target = self.__forward,
                                        args    = [conn, client_sock, stop_event, client_name],
                                        daemon  = True)
        client_thread.start()

        server_thread = threading.Thread(target = self.__forward,
                                        args    = [client_sock, conn, stop_event, client_name],
                                        daemon  = True)
        server_thread.start()

        self.client_threads.append(client_thread)
        self.client_threads.append(server_thread)
        self.client_signals.append(stop_event)

        client_thread.join()
        server_thread.join()

        self.__safe_shutdown(client_sock)
        self.__safe_shutdown(conn)

        logger.info(f"[{client_name}] Connection closed")

    def __run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.server_socket.bind(self.bind_addr)
        self.server_socket.listen()

        logger.info(f"Listening on {self.bind_addr[0]}:{self.bind_addr[1]}")

        while True:
            conn, addr = self.server_socket.accept()
            client_thread = threading.Thread(target = self.__handle_client,
                                            args    = [conn, addr],
                                            daemon  = True)
            self.client_threads.append(client_thread)
            client_thread.start()
    
    def start(self):
        self.__run_server()
    
    def stop(self):
        for signal in self.client_signals:
            signal.set()
        for thread in self.client_threads:
            thread.join()
        self.server_socket.close()

def load_available_proxies():
    with open('proxy_servers.json') as json_file:
        data = json.load(json_file)
    return data

def regen_proxies(num_proxies):
    logger.info(f"Spawning {num_proxies} replacement proxie(s)...")
    LaunchNewSOCKS5.launch(num_proxies)
    logger.info(f"Succesfully spawned {num_proxies} proxie(s)")

def destroy_proxy(available_proxies, proxy):
    ec2.instances.filter(InstanceIds=[proxy['instance_id']]).terminate()
    available_proxies.remove(proxy)
    with open('proxy_servers.json', 'w') as outfile:
        json.dump(available_proxies, outfile)

def main():
    available_proxies = load_available_proxies()
    ideal_proxies = 3

    waitthreads = []

    if len(available_proxies) == 0:
        logger.warning(f"Proxy deficit detected")
        regen_proxies(ideal_proxies)
        available_proxies = load_available_proxies()
    
    if len(available_proxies) < ideal_proxies:
        spawn_thread = threading.Thread(target=regen_proxies, args=[1], daemon=True)
        waitthreads.append(spawn_thread)
        spawn_thread.start()

    proxy = random.choice(available_proxies)
    logger.info(f"Using proxy {proxy['ip']}:{proxy['port']}")
    
    try:
        logger.info("Starting server...")
        fwd_server = ForwardServer('', 1234, proxy)
        fwd_server.start()
    except KeyboardInterrupt as e:
        try:
            print("", end="\r")
            logger.info("Server shutting down...")
            fwd_server.stop()

            if len(waitthreads) > 0:
                logger.info("Waiting for worker threads...")
            for thread in waitthreads:
                thread.join()

            logger.info("Destroying proxy...")
            destroy_proxy(available_proxies, proxy)
        except KeyboardInterrupt as e:
            logger.critical("Ctrl+C pressed twice, forcefully shutting down.")


if __name__ == "__main__":
    main()