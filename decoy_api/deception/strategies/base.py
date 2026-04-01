from abc import ABC, abstractmethod
from fastapi import Request


class BaseStrategy(ABC):

    @abstractmethod
    async def pre_process(self, request: Request) -> None:
        pass

    @abstractmethod
    async def post_process(
        self,
        body: bytes,
        status_code: int,
        path: str,
        session_id: str,
        engine_state: dict,
    ) -> tuple[bytes, int]:
        pass