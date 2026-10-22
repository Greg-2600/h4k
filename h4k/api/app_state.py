# Shared process-level singletons (msf client, cve db).

from services.cve_lookup import CveDb
from services.msfrpc import MsfClient

msf_client: MsfClient | None = None
cve_db: CveDb | None = None

# The engagement whose declared CIDRs now constrain every aggressive action.
# None = operator has not opted into scope enforcement (read-only recon and
# CVE correlation stay available; brute force/exploit demand a scope).
active_engagement_id: str | None = None
