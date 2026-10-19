from . import SIEM
from .cryptosim import CryptoSIM
from .fortisiem import FortiSIEM
from .graylog import Graylog
from .logsign import Logsign
from .qradar import QRadar

SIEM_CLASSES: dict[str, type[SIEM]] = {
    "logsign": Logsign,
    "graylog": Graylog,
    "cryptosim": CryptoSIM,
    "qradar": QRadar,
    "fortisiem": FortiSIEM,
}
