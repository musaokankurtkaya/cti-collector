import time
from collections.abc import Callable
from inspect import Parameter, signature
from json import JSONDecodeError
from json import load as json_load
from os import path as os_path
from pathlib import Path
from typing import Any


def func_measure_time(func: Callable[..., Any]) -> Callable[..., Any]:
    """Measures the time taken for a function to execute and prints it.

    Parameters
    ----------
    func : Callable[..., Any]
        Function to measure the time taken for.

    Returns
    -------
    Callable[..., Any]
        Wrapper function.
    """

    def wrapper(*args, **kwargs):
        start_time: float = time.time()
        func_result: Any = func(*args, **kwargs)
        end_time: float = time.time()
        print(f"{func.__name__} function took {end_time - start_time:.2f}s to execute.")
        return func_result

    return wrapper


def read_json_file(file_path: str | Path, file_name: str) -> Any:
    """Read the json file from the given path & name.

    Parameters
    ----------
    file_path : str | Path
    file_name : str

    Returns
    -------
    Any
        Content of the json file.

    Raises
    ------
    FileNotFoundError
        If the file is not found in the given path.
    ValueError
        If the file is empty.
    JSONDecodeError
        If the file is not a valid JSON file.
    """

    json_file_path: str = os_path.join(file_path, file_name)
    if not os_path.exists(path=json_file_path):
        raise FileNotFoundError(f"{file_name} is not found in {file_path}")

    with open(file=json_file_path, encoding="utf-8") as f:
        try:
            file_content: Any = json_load(fp=f)
            if not file_content:
                raise ValueError(f"{file_name} is empty")
            return file_content
        except JSONDecodeError as e:
            raise JSONDecodeError(
                msg=f"{file_name} is not a valid JSON file", doc=e.doc, pos=e.pos
            )


def get_function_params(
    func: Callable[..., Any], is_self_excluded: bool = True
) -> list[str]:
    """Get the parameters of a function as a list.

    Parameters
    ----------
    func : Callable[..., Any]
        Function to get the parameters for.
    is_self_excluded : bool, optional
        Whether to include the **self** parameter in the result, by default **True**

    Returns
    -------
    list[str]
        List of parameters of the function.
    """

    return [
        param.name
        for param in signature(obj=func).parameters.values()
        if param.kind not in (Parameter.VAR_POSITIONAL, Parameter.VAR_KEYWORD)
        and (not is_self_excluded or param.name != "self")
    ]


def missing_params_exists(
    func: Callable[..., Any],
    expected_params: dict[str, Any],
    is_self_excluded: bool = True,
) -> list[str]:
    """Check if there are any missing parameters in the function.

    Parameters
    ----------
    func : Callable[..., Any]
        Function to check the missing parameters for.
    expected_params : dict[str, Any]
        Expected parameters for the function.
    is_self_excluded : bool, optional
        Whether to include the **self** parameter in the result, by default **True**.

    Returns
    -------
    list[str]
        List of missing parameters in the function if any, otherwise an empty list.
    """

    func_params: set[str] = set(
        get_function_params(func=func, is_self_excluded=is_self_excluded)
    )
    unique_expected_params: set[str] = set(expected_params.keys())

    missing_params: list[str] = list(func_params - unique_expected_params)
    return missing_params
