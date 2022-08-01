import json
from urllib.request import urlopen

import numpy as np
import pandas as pd

import iso3166
import plotly.graph_objs as go
import plotly.express as px
import pydeck as pdk
import altair as alt
import matplotlib.pyplot as plt
import seaborn as sns


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


def make_choropleth_plot(df: pd.DataFrame, projection_type: str = "orthographic"):
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
        geo=dict(showframe=False, showcoastlines=True, projection_type=projection_type),
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
