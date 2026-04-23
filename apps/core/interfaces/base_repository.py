from abc import ABC, abstractmethod
from typing import TypeVar, Generic

T = TypeVar('T')


class IBaseRepository(ABC, Generic[T]):
    @abstractmethod
    def get_by_id(self, entity_id: int) -> T | None:
        ...

    @abstractmethod
    def exists(self, entity_id: int) -> bool:
        ...
