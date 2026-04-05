import threading
from src.server import DNSServer
from src.resolver import IterativeResolver, RecursiveResolver
from src.cache import LRUCache

MAX_CAPICTY = 5


def main():
    threads: list[threading.Thread] = []
    servers = {
        "root": ("data/root.json", 5300),
        "pk": ("data/pk.json", 5301),
        "edu.pk": ("data/edu.pk.json", 5302),
        "nu.edu.pk": ("data/nu.edu.pk.json", 5303),
    }

    try:
        for name, (filename, port) in servers.items():
            cache = LRUCache(MAX_CAPICTY)
            resolver = RecursiveResolver(cache)
            # resolver = IterativeResolver(cache)
            server = DNSServer(filename, resolver, port=port)
            thread = threading.Thread(target=lambda srv: srv.start(), args=(server,))
            threads.append(thread)
            print(f"Starting server {name}")
            thread.start()
    
    except KeyboardInterrupt:
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
