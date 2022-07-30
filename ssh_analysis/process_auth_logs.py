import argparse
import re
import json
from requests import get
from urllib.request import urlopen
from pathlib import Path
from typing import Dict
from enum import Enum
import datetime as dt
import pandas as pd
import numpy as np
from google.protobuf.json_format import MessageToDict

import iso3166
from geoip import geolite2


import plotly.graph_objs as go
import plotly.express as px
import pydeck as pdk

from ssh_analysis.ssh_log_pb2 import SSHLogs, IPLookupData
from ssh_analysis.utils import safe_attr_get, safe_dict_get

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
    logfile: Path, regex_pattern: str = PATTERN, match_map: Dict[str, int] = MATCH_MAP
) -> SSHLogs:

    ssh_logs = SSHLogs()

    with open(logfile) as f:
        for log_entry in f:
            m = re.match(regex_pattern, log_entry)
            if m is not None:
                ssh_logs = add_log_entry(
                    match=m, ssh_logs=ssh_logs, match_map=match_map
                )

    return ssh_logs


def df_from_parsed_logs(ssh_logs: SSHLogs) -> pd.DataFrame:
    def without(d, key):
        d.pop(key)
        return d

    logs = [
        MessageToDict(log, including_default_value_fields=True) for log in ssh_logs.logs
    ]

    logs_with_ip_lookup_data = [
        log["ipLookupData"] | without(log, "ipLookupData") for log in logs
    ]

    return pd.DataFrame.from_records(logs_with_ip_lookup_data)


def get_US_fips_data_from_lat_lon(
    df: pd.DataFrame = None,
    csv_path: Path = None,
    US_fips_data_source: US_FIPS_Source = US_FIPS_Source.FCC_API,
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

    def get_fips(row):
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

        return row

    df_us = df[df["countryIsoCode"] == "US"]
    df_us = df_us.apply(lambda row: get_fips(row), axis=1)

    return df_us


def make_choropleth_plot(df: pd.DataFrame):
    """uses `Plotly` to create a choropleth map of the origin of the nefarious incidents"""

    df_failed_logins = df[~df["validLoginAttempt"]]
    df_clean = df_failed_logins.drop(
        df_failed_logins[df_failed_logins["countryIsoCode"] == ""].index
    )

    df_grouped = (
        df_clean.groupby(["countryIsoCode", "countryName"])
        .size()
        .to_frame("size")
        .reset_index()
    )

    # Convert from two-character abbreviations to three-character
    # abbreviations because `Plotly` cannot handle them.
    df_grouped["countryIsoCode_three_letter"] = df_grouped["countryIsoCode"].apply(
        lambda code: iso3166.countries.get(code).alpha3
    )

    data = [
        dict(
            type="choropleth",
            locations=df_grouped["countryIsoCode_three_letter"],
            z=np.log10(df_grouped["size"]),
            text=df_grouped["countryName"],
            colorscale=[
                [0.00, "rgb(247, 247, 247)"],
                [0.25, "rgb(204, 204, 204)"],
                [0.50, "rgb(150, 150, 150)"],
                [0.75, "rgb( 99,  99,  99)"],
                [1.00, "rgb( 37,  37,  37)"],
            ],
            autocolorscale=False,
            reversescale=False,
            colorbar=dict(
                tickmode="auto",
                title=dict(
                    text="<b>Incidents (log-10)</b>",
                    side="bottom",
                ),
            ),
        )
    ]

    layout = dict(
        title="<b>Failed ssh access attempts</b>",
        # geo=dict(
        #     showframe=False, showcoastlines=True, projection_type="equirectangular"
        # ),
        geo=dict(showframe=False, showcoastlines=True, projection_type="orthographic"),
        margin={"l": 10, "r": 10, "b": 10, "t": 50, "pad": 1000},
        width=1500,
        height=800,
    )

    figure = go.Figure(dict(data=data, layout=layout))

    return figure


def make_pydeck_chart(df_with_lat_lon: pd.DataFrame):
    layer = pdk.Layer(
        "HexagonLayer",  # `type` positional argument is here
        df_with_lat_lon[["lat", "lon"]].dropna(),
        get_position=["lon", "lat"],
        auto_highlight=True,
        elevation_scale=50,
        pickable=True,
        elevation_range=[0, 10000],
        extruded=True,
        coverage=20,
    )

    # layer = pdk.Layer(
    #     'ScatterplotLayer',     # Change the `type` positional argument here
    #     df_with_lat_lon,
    #     get_position=['lon', 'lat'],
    #     auto_highlight=True,
    #     get_radius=10000,          # Radius is given in meters
    #     get_fill_color=[180, 0, 200, 140],  # Set an RGBA value for fill
    #     pickable=True)

    # Set the viewport location
    view_state = pdk.ViewState(
        longitude=-1.415,
        latitude=52.2323,
        zoom=3,
        min_zoom=1,
        max_zoom=15,
        pitch=40.5,
        bearing=-27.36,
    )

    # Combined all of it and render a viewport
    return pdk.Deck(layers=[layer], initial_view_state=view_state)


def make_US_fips_choropleth_plot(df_us: pd.DataFrame, by_county: bool = True):
    with urlopen(
        "https://raw.githubusercontent.com/plotly/datasets/master/geojson-counties-fips.json"
    ) as response:
        counties = json.load(response)

    # by county
    if by_county:
        group = "county_fips"
        locationmode = None
    # by state
    else:
        group = "state_code"
        locationmode = "USA-states"

    df_grouped = df_us.groupby(group).size().to_frame("size").reset_index()

    fig = px.choropleth(
        df_grouped,
        geojson=counties,
        locations=group,
        color="size",
        color_continuous_scale="Viridis",
        range_color=(0, 200),
        scope="usa",
        labels={"size": "number of ssh attempts"},
        locationmode=locationmode,
    )
    fig.update_layout(margin={"r": 0, "t": 0, "l": 0, "b": 0})

    return fig


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("INPUT", nargs="+", help="Input files")

    args = parser.parse_args()
