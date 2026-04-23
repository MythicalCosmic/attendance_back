from django.db import models


class BaseRepository:
    model: type[models.Model] = None

    def __init__(self, organization_id: int | None = None):
        self._org_id = organization_id

    def _base_queryset(self) -> models.QuerySet:
        qs = self.model.objects.all()
        if self._org_id and hasattr(self.model, 'organization_id'):
            qs = qs.filter(organization_id=self._org_id)
        if hasattr(self.model, 'is_deleted'):
            qs = qs.filter(is_deleted=False)
        return qs

    def get_by_id(self, entity_id: int):
        return self._base_queryset().filter(id=entity_id).first()

    def exists(self, entity_id: int) -> bool:
        return self._base_queryset().filter(id=entity_id).exists()
