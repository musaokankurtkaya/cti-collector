from pathlib import Path

from src.config import load_config

ROOT_FOLDER_PATH: Path = Path(__file__).parent.parent.parent

PROJECT_FOLDER_PATH: Path = ROOT_FOLDER_PATH / "src"

LOG_FOLDER_PATH: Path = ROOT_FOLDER_PATH / "logs"

DATA_FOLDER_PATH: Path = PROJECT_FOLDER_PATH / "data"

ATTACK_TAGS_JSON_FILE_PATH: Path = DATA_FOLDER_PATH / "siems" / "attack_tags.json"

EXCLUDED_IPS_JSON_FILE_PATH: Path = DATA_FOLDER_PATH / "siems" / "excluded_ips.json"

COUNTRIES_JSON_FILE_PATH: Path = DATA_FOLDER_PATH / "ipinfo" / "countries.json"

CONFIG: dict[str, dict[str, str]] = load_config()

DEFAULT_ENV: str = "dev"

APP_ENV: str = CONFIG.get("app", {}).get("env", DEFAULT_ENV)

IS_PROD: bool = APP_ENV == "prod"

QUERY_INTERVAL: int = int(CONFIG.get("app", {}).get("query_interval", 15))

QUERY_LIMIT: int = int(CONFIG.get("app", {}).get("query_limit", 9999))
