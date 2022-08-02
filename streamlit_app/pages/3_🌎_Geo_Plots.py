from uuid import uuid4
import streamlit as st
from ssh_analysis.visuals import (
    make_choropleth_plot,
    make_pydeck_chart,
    make_US_fips_choropleth_plot,
    PYDECK_LAT_LON_LAYER_KWARGS,
)
from streamlit_app.utils import run_data_app, date_slider_filter_data, dict_input

st.set_page_config(page_title="Geospatial Visualizations", page_icon="🌎", layout="wide")

st.markdown("# Geospatial Visualizations")
st.markdown(
    """
    Since we have Lat/Lon data from GeoIP lookups, we can look at the geospatial distribution of access attempts.
    """
)


def data_app(data):

    with st.expander("Global Choropleth"):
        projections_2d = [
            "equirectangular",
            "mercator",
            "orthographic",
            "natural earth",
            "kavrayskiy7",
            "miller",
            "robinson",
            "eckert4",
            "azimuthal equal area",
            "azimuthal equidistant",
            "conic equal area",
            "conic conformal",
            "conic equidistant",
            "gnomonic",
            "stereographic",
            "mollweide",
            "hammer",
            "transverse mercator",
            "albers usa",
            "winkel tripel",
            "aitoff",
            "sinusoidal",
        ]

        col1, col2 = st.columns((1, 2), gap="large")  # To make it narrower
        projection = col1.selectbox(
            "Which map projection would you like to use?",
            projections_2d,
            index=2,
        )
        filtered_data = date_slider_filter_data(
            col2, data, streamlit_widget_key="slider-1"
        )

        st.plotly_chart(
            make_choropleth_plot(
                df=filtered_data, projection_type=projection, width=2000, height=800
            ),
            use_container_width=True,
        )

    with st.expander("PyDeck Lat/Lon Viz"):
        col4, col5 = st.columns((1, 3), gap="large")

        filtered_data = date_slider_filter_data(
            col5, data, streamlit_widget_key="slider-2"
        )
        viz_type = col5.selectbox(
            "Deck Layer",
            ["HexagonLayer", "ScatterplotLayer"],
            index=0,
        )

        # json input widget usefully remembers state between runs so you can keep editing, but we don't want that
        if ("deck_options_key" in st.session_state) and (
            viz_type in st.session_state.deck_options_key
        ):
            pass
        else:
            st.session_state.deck_options_key = {}
            st.session_state.deck_options_key[viz_type] = uuid4()

        with col4:
            layer_kwargs = dict_input(
                "Layer Options",
                value=PYDECK_LAT_LON_LAYER_KWARGS[viz_type],
                mutable_structure=True,
                key=st.session_state.deck_options_key[viz_type],
            )
        st.pydeck_chart(
            make_pydeck_chart(
                df_with_lat_lon=filtered_data,
                viz_type=viz_type,
                layer_kwargs=layer_kwargs,
            ),
            use_container_width=True,
        )

    with st.expander("US State/County Choropeth"):
        st.markdown("")
        if "data_US_FIPS" not in st.session_state:
            st.warning(
                "You need to load the US FIPS data (after loading logs) before you can visualize login attempts by US State/County - this relies on correlating IPs <-> county FIPS codes."
            )
        else:
            login_aggregation_level = st.selectbox(
                "Aggregate Login Attempts By", options=("State", "County"), index=1
            )
            if login_aggregation_level == "State":
                by_county = False
            elif login_aggregation_level == "County":
                by_county = True
            st.plotly_chart(
                make_US_fips_choropleth_plot(
                    df_us=st.session_state.data_US_FIPS, by_county=by_county
                ),
                use_container_width=True,
            )


run_data_app(data_app=data_app)
