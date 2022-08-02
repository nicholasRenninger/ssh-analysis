import re
from requests import get
import requests
from pathlib import Path
from typing import Dict, TextIO, Tuple
from enum import Enum
import datetime as dt
import pandas as pd
from io import StringIO
from google.protobuf.json_format import MessageToJson

from geoip import geolite2

from ssh_analysis.ssh_log_pb2 import SSHLogs, IPLookupData
from ssh_analysis.utils import safe_attr_get, safe_dict_get, update_progress_bar

PATTERN = r"(\w+\s\d+\s\d+:\d+:\d+)\s.*?(Failed|Accepted)\spassword\sfor\s(invalid\suser\s)?(.+?)\sfrom\s(.+)\sport\s(\d+)"
MATCH_MAP = {
    "timestamp": 1,
    "validLoginAttempt": 2,
    "usernameIsValid": 3,
    "user": 4,
    "ipAddress": 5,
    "port": 6,
}


class US_FIPS_Source(Enum):
    FCC_API = "fcc_api"
    CSV = "csv"


def get_data_paths(
    use_demo_data: bool = True, data_dir: Path = Path("../data/")
) -> Tuple[Path, Path]:

    # shouldn't need to touch this
    log_filename = "auth.log"
    df_us_csv_filename = "df_us.csv"

    if use_demo_data:
        log_file_path = data_dir / Path(log_filename)
        r = requests.get(
            "https://raw.githubusercontent.com/elastic/examples/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log"
        )
        with open(file=log_file_path, mode="w+") as f:
            f.write(r.text)

        path_df_us_fips_csv = data_dir / Path(df_us_csv_filename)
    else:
        log_file_path = data_dir / Path(f"my_{log_filename}")
        path_df_us_fips_csv = data_dir / Path(f"my_{df_us_csv_filename}")

    return log_file_path, path_df_us_fips_csv


def lookup_ip(ip_address: str) -> IPLookupData:
    """
    Given an IP address, return GeoIP data
    """

    result = geolite2.lookup(ip_address)

    ip_lookup_data = IPLookupData()

    if result:
        data = result.get_info_dict()

        continent = safe_attr_get(result, "continent")

        country = safe_dict_get(data, "country")
        country_iso_code = safe_dict_get(country, "iso_code")
        country_name = f"{safe_dict_get(country, 'names', 'en')} ({country_iso_code})"
        subdivisions = [div for div in safe_attr_get(result, "subdivisions")]

        city = safe_dict_get(data, "city", "names", "en")
        postal_code = safe_dict_get(data, "postal", "code")
        location = safe_attr_get(result, "location")
        if location is not None:
            lat, lon = location
        else:
            lat = lon = None

        timezone = safe_attr_get(result, "timezone")

        ip_lookup_data = IPLookupData(
            lat=lat,
            lon=lon,
            continent=continent,
            country_iso_code=country_iso_code,
            country_name=country_name,
            subdivisions=subdivisions,
            timezone=timezone,
            postal_code=postal_code,
            city=city,
        )

    return ip_lookup_data


def add_log_entry(match, ssh_logs: SSHLogs, match_map: Dict[str, int]) -> SSHLogs:
    log = ssh_logs.logs.add()
    datetime_fmt = "%b %d %H:%M:%S"

    log.timestamp.FromDatetime(
        dt.datetime.strptime(match[match_map["timestamp"]], datetime_fmt).replace(
            year=2022
        )
    )
    log.validLoginAttempt = (
        True if match[match_map["validLoginAttempt"]] == "Accepted" else False
    )
    if match[match_map["usernameIsValid"]] is not None:
        log.usernameIsValid = False
    else:
        log.usernameIsValid = True

    log.user = match[match_map["user"]]
    log.ipAddress = match[match_map["ipAddress"]]
    log.port = int(match[match_map["port"]])

    log.ipLookupData.CopyFrom(lookup_ip(ip_address=log.ipAddress))

    return ssh_logs


def parse_logs(
    logfile_path: Path = None,
    logfile: TextIO = None,
    regex_pattern: str = PATTERN,
    match_map: Dict[str, int] = MATCH_MAP,
    progress_bar=None,
    status_text=None,
) -> SSHLogs:

    if not ((logfile_path is None) ^ (logfile is None)):
        raise ValueError(
            f"must supply EITHER open logfile ({logfile}) or logfile_path ({logfile_path})"
        )

    def parse(f: TextIO, progress_bar) -> SSHLogs:
        ssh_logs = SSHLogs()

        num_lines = sum(1 for line in f)
        f.seek(0)
        for i, log_entry in enumerate(f):
            m = re.match(regex_pattern, log_entry)
            if m is not None:
                ssh_logs = add_log_entry(
                    match=m, ssh_logs=ssh_logs, match_map=match_map
                )

            update_progress_bar(progress_bar, status_text, i, num_lines)

        return ssh_logs

    if logfile_path:
        with open(logfile_path) as f:
            return parse(f, progress_bar)

    if logfile:
        return parse(logfile, progress_bar)


def df_from_parsed_logs(ssh_logs: SSHLogs) -> pd.DataFrame:

    json_logs = StringIO()

    # IDK why, but the protobuf msg->json includes a ton of extra newlines that will break
    # reading the df as newline-delimited JSON
    for log in ssh_logs.logs:
        json_logs.write(
            MessageToJson(log, including_default_value_fields=True).replace("\n", "")
            + "\n"
        )

    # we want to use read_json because it will properly infer the types (especially date times)
    df = pd.read_json(json_logs.getvalue(), lines=True)

    # the embedded ipLookipData types is a neted dict per record, so to normalize (flatten),
    # we normalize and then join on the index
    df_meta = pd.json_normalize(list(df["ipLookupData"]))
    df = df.drop("ipLookupData", axis=1).join(df_meta)

    # add datetime breakdown for analytic convenience
    df["date"] = df["timestamp"].dt.date
    df["week"] = df["timestamp"].dt.isocalendar().week
    df["hour"] = df["timestamp"].dt.hour

    return df


def get_US_fips_data_from_lat_lon(
    df: pd.DataFrame = None,
    csv_path: Path = None,
    US_fips_data_source: US_FIPS_Source = US_FIPS_Source.FCC_API,
    progress_bar=None,
    status_text=None,
) -> pd.DataFrame:

    if US_fips_data_source == US_FIPS_Source.CSV:
        if csv_path is not None:

            # need to ensure we read the code fields as strings, as they often start with 0s. If you read them in as ints
            # then you will lose the 0XX part of the code and they code won't match a standard FIPS code
            df_us = pd.read_csv(
                csv_path,
                converters={"postalCode": str, "county_fips": str, "state_fips": str},
            ).drop(["Unnamed: 0"], axis=1)
            return df_us
        else:
            raise ValueError(f"csv_path must not be none when loading from CSV")

    if df is None:
        raise ValueError("df must not be None if loading from FCC source")

    BASE_URL = "https://geo.fcc.gov/api/census/area?lat={lat}&lon={lon}&format=json"

    def get_fips(row, num_rows, progress_bar=None, status_text=None):
        lat = row["lat"]
        lon = row["lon"]

        hdr = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://cssspritegenerator.com",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
            "Accept-Encoding": "none",
            "Accept-Language": "en-US,en;q=0.8",
            "Connection": "keep-alive",
        }

        url = BASE_URL.format(lat=lat, lon=lon)
        d = get(url, headers=hdr)

        data = d.json()["results"][0]
        row["county_fips"] = data["county_fips"]
        row["county_name"] = data["county_name"]
        row["state_fips"] = data["state_fips"]
        row["state_code"] = data["state_code"]
        row["state_name"] = data["state_name"]

        update_progress_bar(progress_bar, status_text, row.index, num_lines=num_rows)

        return row

    df_us = df[df["countryIsoCode"] == "US"]
    df_us = df_us.apply(
        lambda row: get_fips(
            row,
            len(df_us),
            progress_bar=progress_bar,
            status_text=status_text,
        ),
        axis=1,
    )

    return df_us
