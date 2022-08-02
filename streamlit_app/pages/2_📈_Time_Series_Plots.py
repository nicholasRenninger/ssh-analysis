import streamlit as st
from ssh_analysis.visuals import make_ridge_plot, make_altair_bar_chart
from streamlit_app.utils import run_data_app

st.set_page_config(page_title="Time Series Plots", page_icon="📈", layout="wide")

st.markdown("# Time Series Plots")
st.markdown(
    """
    Now that we've loaded the data, we can do some basic time-series plotting of the different facets.
    """
)


def data_app(data):
    categories = st.selectbox(
        "Which facet would you like to visualize over time? (some good ones are usernameIsValid, countryName, user, ipAddress)",
        sorted(data.columns),
        index=16,  # "validLoginAttempt"
    )

    st.write(
        make_altair_bar_chart(
            df=data, categories=categories, disable_max_rows_error=True
        )
    )

    with st.expander("Time-of-day"):
        st.markdown(
            """
            We can also visualize the access-attempt distributions per hour of the day to see if there is a preferred time-of-day for an attack:
            """
        )
        if st.button("Show Ridge Plot"):
            _, plot = make_ridge_plot(df=data)
            st.pyplot(plot)


run_data_app(data_app=data_app)
