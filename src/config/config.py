from configparser import ConfigParser
from pathlib import Path


def load_config(conf_file_name: str = "config.ini") -> dict[str, dict[str, str]]:
    """Reads the configuration file and returns the settings as a dictionary.

    Parameters
    ----------
    conf_file_name: str, optional
        The name of the configuration file to read, by default "config.ini".

    Returns
    -------
    dict[str, dict[str, str]]
        Configuration settings if the file exists, otherwise an empty dictionary.

    Examples
    --------
    >>> load_config()
    {
        "section1": {
            "key1": "value1",
        },
        "section2": {
            "key2": "value2",
        }
    }
    """

    config_parser: ConfigParser = ConfigParser(interpolation=None)

    config_file_path: Path = Path(__file__).parent / conf_file_name
    if not config_file_path.exists():
        return {}

    config_parser.read(filenames=config_file_path, encoding="utf-8")

    return {s: dict(config_parser.items(section=s)) for s in config_parser.sections()}
