# Shared process-level singletons (msf client).
from typing import Optional

from services.msfrpc import MsfClient

msf_client: Optional[MsfClient] = None
