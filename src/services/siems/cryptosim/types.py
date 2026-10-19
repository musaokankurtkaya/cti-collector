from typing import TypedDict


class Data(TypedDict, total=False):
    """CryptoSIM search response data type"""

    plgid: str
    ts: str
    date1: str
    subtype: str
    rurl: str
    sessionid: str
    origin: str
    product: str
    cs3: str
    flexString2: str
    attack: str
    catid: str
    catsvr: str
    type: str
    svr: str
    action: str
    src_port: str
    dst_port: str
    dst_ip: str
    proto: str
    src_ip: str
    dhost: str
    apppro: str
    sco: str
    dco: str
    dvcname: str
    rnum: str
    sint: str
    dint: str
    plugin_sid: str


class SearchResponse(TypedDict, total=False):
    """Cryptosim search response type.

    Attributes
    ----------
    StatusCode : int
        The status code of the response.
    ErrorMessage : str, optional
        The error message if exists.
    Data : list[Data]
        The list of searched data.
    """

    StatusCode: int
    ErrorMessage: str | None
    Data: list[Data]


type CryptoSIMSearchedEventResponse = Data

type CryptoSIMSearchedEvents = list[CryptoSIMSearchedEventResponse]
