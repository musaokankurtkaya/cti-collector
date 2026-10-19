from src.utils.constants import CONFIG, COUNTRIES_JSON_FILE_PATH
from src.utils.globals import read_json_file

from ..http_client import HttpClient, Response, log_message
from .types import Country, IpInfoResponse


class IpInfo:
    """IpInfo class to interact with IpInfo's API.

    For more details, see [IpInfo REST API](https://ipinfo.io/developers/ipinfo-api)
    """

    @classmethod
    def get_ip_info(cls, ip: str) -> tuple[str, str]:
        """Get country name, latitude and longitude of the IP address.

        Parameters
        ----------
        ip : str
            The IP address to get the country name, latitude and longitude of.

        Returns
        -------
        tuple[str, str]
            The country name, latitude and longitude of the IP address.
        """

        country_code, geo_loc = cls.fetch_ip_info(ip=ip)
        country_name: str = cls.get_country_name_by_code(country_code=country_code)
        return country_name, geo_loc

    @classmethod
    def fetch_ip_info(cls, ip: str) -> tuple[str, str]:
        """Fetch country code, latitude and longitude of the IP address.

        Parameters
        ----------
        ip : str
            The IP address to fetch the country code, latitude and longitude of.

        Returns
        -------
        tuple[str, str]
            The country code, latitude and longitude of the IP address.
        """

        url, token = cls.get_ipinfo_credentials()
        params: dict[str, str] = {"token": token}
        if not token:
            log_message(
                mode="error",
                msg="ipinfo token not found in the config.ini, request will be sent without the token!",
            )
            params = {}

        http_client: HttpClient = HttpClient(url=url, verify=True)

        ipinfo_response: Response | None = http_client.request(
            method="get", endpoint=f"/{ip}/json", params=params
        )

        default_country_code: str = "Unknown"
        default_geo_loc: str = "0,0"
        if ipinfo_response is None:
            return default_country_code, default_geo_loc

        ipinfo_ip_data: IpInfoResponse = ipinfo_response.json()

        country_code: str = ipinfo_ip_data.get("country", default_country_code)
        geo_loc: str = ipinfo_ip_data.get("loc", default_geo_loc)

        if country_code == default_country_code or geo_loc == default_geo_loc:
            error_msg: str = f"ipinfo: country will be Unknown, latitude & longitude will be 0.0, location or country not found for ip {ip}"
            log_message(mode="error", msg=error_msg)

        return country_code, geo_loc

    @staticmethod
    def get_ipinfo_credentials() -> tuple[str, str]:
        """Get IpInfo credentials from the config.ini file.

        Returns
        -------
        tuple[str, str]
            The IpInfo url and token.
        """

        ipinfo_config: dict[str, str] = CONFIG.get("ipinfo", {})
        url: str = ipinfo_config.get("url", "https://ipinfo.io")
        token: str = ipinfo_config.get("token", "")
        return url, token

    @staticmethod
    def get_country_name_by_code(country_code: str) -> str:
        """Get country name by country code.

        Parameters
        ----------
        country_code : str
            The country code to get the country name of.

        Returns
        -------
        str
            The country name of the country code. If the country name is not found, it returns "Unknown".
        """

        default_country_name: str = "Unknown"

        countries: list[Country] = read_json_file(
            file_path=COUNTRIES_JSON_FILE_PATH.parent,
            file_name=COUNTRIES_JSON_FILE_PATH.name,
        )
        if not countries:
            error_msg: str = (
                "countries.json file is empty, country name will be Unknown!"
            )
            log_message(mode="error", msg=error_msg)
            return default_country_name

        return next(
            (c["country"] for c in countries if c["iso2"] == country_code),
            default_country_name,
        )
