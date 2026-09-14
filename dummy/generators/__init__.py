from .base_generator import BaseGenerator

try:
    from .asset_generator import AssetGenerator
except ImportError:
    AssetGenerator = None

try:
    from .wazuh_generator import WazuhGenerator
except ImportError:
    WazuhGenerator = None

try:
    from .suricata_generator import SuricataGenerator
except ImportError:
    SuricataGenerator = None

try:
    from .fortigate_generator import FortiGateGenerator
except ImportError:
    FortiGateGenerator = None

try:
    from .ad_generator import ADGenerator
except ImportError:
    ADGenerator = None

try:
    from .edr_generator import EDRGenerator
except ImportError:
    EDRGenerator = None

try:
    from .misp_generator import MISPGenerator
except ImportError:
    MISPGenerator = None

try:
    from .iris_generator import IRISGenerator
except ImportError:
    IRISGenerator = None

try:
    from .ukweli_generator import UKWELIGenerator
except ImportError:
    UKWELIGenerator = None

__all__ = [
    "BaseGenerator",
    "AssetGenerator",
    "WazuhGenerator",
    "SuricataGenerator", 
    "FortiGateGenerator",
    "ADGenerator",
    "EDRGenerator",
    "MISPGenerator",
    "IRISGenerator",
    "UKWELIGenerator"
]
