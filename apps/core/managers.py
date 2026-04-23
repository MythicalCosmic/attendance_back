from django.db import models


class TenantAwareManager(models.Manager):
    def for_organization(self, organization_id: int):
        return self.filter(organization_id=organization_id)

    def active(self):
        return self.filter(is_deleted=False, is_active=True)
