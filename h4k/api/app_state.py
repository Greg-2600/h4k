# Shared process-level singletons (msf client, cve db).

from services.cve_lookup import CveDb
from services.msfrpc import MsfClient

msf_client: MsfClient | None = None
cve_db: CveDb | None = None
