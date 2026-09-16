# Shared process-level singletons (msf client, cve db).
from typing import Optional

from services.cve_lookup import CveDb
from services.msfrpc import MsfClient

msf_client: Optional[MsfClient] = None
cve_db: Optional[CveDb] = None
