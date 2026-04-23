from pydantic import BaseModel, field_validator


class PaginationParams(BaseModel):
    page: int = 1
    per_page: int = 20

    @field_validator('per_page')
    @classmethod
    def cap_per_page(cls, v: int) -> int:
        return min(max(v, 1), 100)

    @field_validator('page')
    @classmethod
    def min_page(cls, v: int) -> int:
        return max(v, 1)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


class PaginationMeta(BaseModel):
    page: int
    per_page: int
    total: int
    total_pages: int

    @classmethod
    def build(cls, page: int, per_page: int, total: int) -> 'PaginationMeta':
        return cls(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page if total > 0 else 0,
        )
