#!/usr/bin/env python

from pathlib import Path
from sys import path as sys_path

if not __package__:
    file_path: Path = Path(__file__).resolve()
    root_path: str = file_path.parent.parent.as_posix()
    sys_path.insert(0, root_path)


if __name__ == "__main__":
    # setup logging configuration
    from src.utils.logger import log_message, setup_logger

    setup_logger()

    # run main app
    from src.app import main
    from src.utils.constants import APP_ENV

    try:
        log_message(mode="info", msg=f"running on {APP_ENV} mode")
        main()
    except Exception as e:  # noqa: BLE001
        log_message(mode="critical", msg=f"unexpected error occured: {e}")
    except KeyboardInterrupt:
        log_message(mode="info", msg="app interrupted by the user")
