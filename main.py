import os
import threading
from src.server import DNSServer
from src.resolver import IterativeResolver, RecursiveResolver
from src.cache import LRUCache

MAX_CAPICTY = 5


def main():
    threads: list[threading.Thread] = []

    with os.scandir("data") as entries:
        for entry in entries:
            if not entry.is_file():
                continue
            cache = LRUCache(MAX_CAPICTY)
            resolver = RecursiveResolver(cache)
            # resolver = IterativeResolver(cache)
            server = DNSServer(entry.path, resolver)
            thread = threading.Thread(target=lambda srv: srv.start(), args=(server,))
            threads.append(thread)

    try:
        for thread in threads:
            thread.start()
    except KeyboardInterrupt:
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
