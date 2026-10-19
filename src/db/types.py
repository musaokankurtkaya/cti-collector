from dataclasses import dataclass, field

from bson import ObjectId


@dataclass
class MongoDbEvent:
    """Event type in MongoDB.

    Attributes
    ----------
    event_type: str
        Which type of event based on defined in customer conf. (e.g ips, waf etc.)
    src_ip : str
        Source IP address of the event.
    customer_name : str
        Customer name of the event.
    sector : str
        Sector of customer.
    first_seen : str
        First seen date of the event. (e.g. '2021-09-01 00:00:00')
    _id: ObjectId, optional
        Unique MongoDb document id.
    last_seen : list[str]
        Last seens date of the event. (e.g. ['2021-09-01 00:00:00', '2023-04-25 22:30:00'])
    attack_name : list[str]
        Attack names of the event.
    attack_category : list[str]
        Attack categories of the event.
    dst_port : list[int]
        Seen destination ports of the event.
    number_of_occurrences : int
        Number of occurrences of the event.
    score : int, optional
        Score of the IP address.
    severity : str, optional
        Severity of the event.
    country : str, optional
        Country of the source IP address.
    loc : str, optional
        Latitude and longitude of the source IP address.
    """

    event_type: str
    src_ip: str
    customer_name: str
    sector: str
    first_seen: str
    _id: ObjectId | None = None
    last_seen: list[str] = field(default_factory=list)
    attack_name: list[str] = field(default_factory=list)
    attack_category: list[str] = field(default_factory=list)
    dst_port: list[int] = field(default_factory=list)
    number_of_occurrences: int = 1
    score: int | None = None
    severity: str | None = None
    country: str | None = None
    loc: str | None = None
