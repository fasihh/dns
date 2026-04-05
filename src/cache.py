from abc import ABC, abstractmethod
from collections import OrderedDict


class Cache(ABC):
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.cache = {}

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __delitem__(self, key):
        return self.delete(key)

    def __contains__(self, key):
        return self.get(key) is not None

    @abstractmethod
    def get(self, key):
        raise NotImplementedError

    @abstractmethod
    def set(self, key, item):
        raise NotImplementedError

    @abstractmethod
    def delete(self, key):
        raise NotImplementedError


class LRUCache(Cache):
    def __init__(self, capacity: int):
        super().__init__(capacity)
        self.cache = OrderedDict()

    def get(self, key):
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)  # mark as recently used
        return self.cache[key]

    def set(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)  # flush least recently used

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]


class SimpleCache(Cache):
    def __init__(self, capacity: int):
        super().__init__(capacity)
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def set(self, key, value):
        if key in self.cache:
            self.cache[key] = value
            return

        if len(self.cache) >= self.capacity and self.cache:
            # drop any entry available
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        self.cache[key] = value

    def delete(self, key):
        if key in self.cache:
            del self.cache[key]
