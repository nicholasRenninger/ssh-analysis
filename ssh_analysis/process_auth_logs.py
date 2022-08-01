import argparse
from cmath import log
import re
import json
from requests import get
from urllib.request import urlopen
import requests
from pathlib import Path
from typing import Dict, TextIO, Tuple
from enum import Enum
import datetime as dt
import pandas as pd
import numpy as np
from io import StringIO, TextIOWrapper
from google.protobuf.json_format import MessageToJson

import iso3166
from geoip import geolite2


import altair as alt
import matplotlib.pyplot as plt
import seaborn as sns
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


def get_data_paths(
    use_demo_data: bool = True,
) -> Tuple[Path, Path]:

    # shouldn't need to touch this
    data_dir = Path("../data/")
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
) -> SSHLogs:

    if not ((logfile_path is None) ^ (logfile is None)):
        raise ValueError(
            f"must supply EITHER open logfile ({logfile}) or logfile_path ({logfile_path})"
        )

    def parse(f: TextIO) -> SSHLogs:
        ssh_logs = SSHLogs()

        for log_entry in f:
            m = re.match(regex_pattern, log_entry)
            if m is not None:
                ssh_logs = add_log_entry(
                    match=m, ssh_logs=ssh_logs, match_map=match_map
                )
        return ssh_logs

    if logfile_path:
        with open(logfile_path) as f:
            return parse(f)

    if logfile:
        return parse(logfile)


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
    df["date"] = df["timestamp"].dt.date.astype(str)
    df["week"] = df["timestamp"].dt.isocalendar().week.astype(str)
    df["hour"] = df["timestamp"].dt.hour.astype(str)

    return df


def make_ridge_plot(df: pd.DataFrame):

    sns.set_style("ticks")
    sns.set_theme(style="white", rc={"axes.facecolor": (0, 0, 0, 0)})

    from numpy import float64

    groups = [
        "date",
        "hour",
        "ipAddress",
        "validLoginAttempt",
        "countryName",
        "user",
        "usernameIsValid",
    ]
    df_grouped = df.groupby(groups).size().to_frame("login attempts").reset_index()
    df_g = (
        df_grouped.groupby(["date", "hour"])
        .sum()
        .reset_index()[["hour", "login attempts"]]
    )
    df_g["login attempts"] = df_g["login attempts"].astype(float64)
    df_g["hour"] = df_g["hour"].astype(int)
    df_g.sort_values(by=["hour"], ascending=True, inplace=True)
    df_g["hour"] = df_g["hour"].astype(str)

    # Initialize the FacetGrid object
    pal = sns.cubehelix_palette(24, rot=-0.25, light=0.7)
    g = sns.FacetGrid(df_g, row="hour", hue="hour", aspect=15, height=0.5, palette=pal)

    # Draw the densities in a few steps
    g.map(
        sns.kdeplot,
        "login attempts",
        bw_adjust=0.9,
        common_norm=True,
        clip_on=False,
        fill=True,
        alpha=1,
        linewidth=1.5,
    )
    g.map(
        sns.kdeplot,
        "login attempts",
        clip_on=False,
        color="w",
        lw=2,
        bw_adjust=0.9,
        common_norm=True,
    )

    # passing color=None to refline() uses the hue mapping
    g.refline(y=-0.00001, linewidth=2, linestyle="-", color=None, clip_on=True)

    # Define and use a simple function to label the plot in axes coordinates
    def label(x, color, label):
        ax = plt.gca()
        ax.text(
            0,
            0.2,
            label,
            fontweight="bold",
            color=color,
            ha="left",
            va="center",
            transform=ax.transAxes,
        )

    g.map(label, "login attempts")

    # Set the subplots to overlap
    g.figure.subplots_adjust(hspace=-0.35)

    # Remove axes details that don't play well with overlap
    g.set_titles("")
    g.set(yticks=[], ylabel="")
    g.despine(bottom=True, left=True)

    return df_g, g


def make_altair_bar_chart(
    df: pd.DataFrame, categories: str, disable_max_rows_error: bool = False
):

    # these plots can be enormous and they're raw JSON, so normally altair stops you from doing this to
    # not have massive jupyter files saved...
    if disable_max_rows_error:
        alt.data_transformers.disable_max_rows()

    area = (
        alt.Chart(df)
        .mark_bar(cornerRadius=3, width=20, align="left")
        .encode(
            x=alt.X("date:T", axis=alt.Axis(labelAngle=40)),
            y=alt.Y("num_access:Q", title="# ssh login attempts"),
            color=alt.Color(categories, scale=alt.Scale(scheme="category20")),
            tooltip=["date:T", categories, "num_access:Q"],
        )
        .transform_aggregate(
            num_access=f"count({categories})", groupby=["date", categories]
        )
        .properties(width=1200, height=400)
    )

    return area


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
