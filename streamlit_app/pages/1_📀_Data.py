from enum import Enum
from io import StringIO
from typing import TextIO
from matplotlib import use
import streamlit as st
import pandas as pd
from pathlib import Path
from google.protobuf.json_format import MessageToDict

from streamlit_app.utils import my_AgGrid
from ssh_analysis.process_auth_logs import (
    US_FIPS_Source,
    get_data_paths,
    get_US_fips_data_from_lat_lon,
    lookup_ip,
    parse_logs,
    df_from_parsed_logs,
)


st.set_page_config(page_title="Data", page_icon="📀")

st.markdown("# Data")
# st.sidebar.header("Data")
st.markdown(
    """
Before you can run the analysis, you need your SSH log data. SSH logs can be found in `/var/log/auth.log` and have a structure like:
```bash
Mar 27 13:06:56 ip-10-77-20-248 sshd[1291]: Server listening on 0.0.0.0 port 22.
Mar 27 13:06:56 ip-10-77-20-248 sshd[1291]: Server listening on :: port 22.
Mar 27 13:06:56 ip-10-77-20-248 systemd-logind[1118]: Watching system buttons on /dev/input/event0 (Power Button)
Mar 27 13:06:56 ip-10-77-20-248 systemd-logind[1118]: Watching system buttons on /dev/input/event1 (Sleep Button)
Mar 27 13:06:56 ip-10-77-20-248 systemd-logind[1118]: New seat seat0.
Mar 27 13:08:09 ip-10-77-20-248 sshd[1361]: Accepted publickey for ubuntu from 85.245.107.41 port 54259 ssh2: RSA SHA256:Kl8kPGZrTiz7g4FO1hyqHdsSBBb5Fge6NWOobN03XJg
Mar 27 13:08:09 ip-10-77-20-248 sshd[1361]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
...
```

This app includes a "demo" dataset if you don't have one to analyze, which is from [elastic's example datasets](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log).
"""
)
with st.expander("How to get a logfile"):
    st.markdown(
        """
    You can do this via:

    ```bash
    ll /var/log/auth.*
    sudo gzip -d /var/log/auth.log.*.gz
    sudo cat /var/log/auth.* > ~/Desktop/my_auth.log
    ```

    You should now have all of your `/var/log/auth.log` concatenated into one file, `~/Desktop/my_auth.log`. You should now move this file to the root of the `ssh_analysis` directory. Assuming you cloned `ssh_analysis` to `~/git`:

    ```bash
    mv ~/Desktop/my_auth.log ~/git/ssh_analysis/data/my_auth.log
    ```
        """
    )

with st.expander("IP Address Lookups"):
    st.markdown(
        """
        Metadata associated with an IP address can be queried from online geo-coding services or from geolite2 DBs. This project uses [an older, self-contained geolite2 package](https://pythonhosted.org/python-geoip/). You could easily modify this example to use a more accurate geoIP DB by modifying this function that maps an IP address to an `IPLookupData` object.

        Here, you can try out the IP lookup functionality that is used:
        """
    )

    IP = st.text_input("IP Address", "197.255.225.94")
    st.table(
        pd.DataFrame(
            [MessageToDict(lookup_ip(IP), including_default_value_fields=True)]
        )
    )


class DS(str, Enum):
    DEMO = "Demo"
    NICK = "Nick's"
    UPLOAD = "Upload My Own"


@st.experimental_memo(suppress_st_warning=True)
def get_data(logfile: TextIO, log_file_path: Path):

    progress_bar = st.sidebar.progress(0)
    status_text = st.sidebar.empty()

    ssh_logs = parse_logs(
        logfile=logfile,
        logfile_path=log_file_path,
        progress_bar=progress_bar,
        status_text=status_text,
    )
    progress_bar.empty()
    status_text.text(f"Done processing. Logs Analyzed")

    return df_from_parsed_logs(ssh_logs)


@st.experimental_memo(suppress_st_warning=True)
def get_data_US_FIPS(
    data: pd.DataFrame, csv_path: Path, _US_fips_data_source: US_FIPS_Source
):
    progress_bar = st.sidebar.progress(0)
    status_text = st.sidebar.empty()

    df_us = get_US_fips_data_from_lat_lon(
        df=data,
        csv_path=csv_path,
        US_fips_data_source=US_fips_data_source,
        progress_bar=progress_bar,
        status_text=status_text,
    )
    progress_bar.empty()
    status_text.text(f"US FIPS Data Loaded")

    return df_us


@st.cache
def convert_df(data: pd.DataFrame):
    # IMPORTANT: Cache the conversion to prevent computation on every rerun
    return data.to_csv(index=False).encode("utf-8")


data_source = st.selectbox(
    "Which source of data would you like to use?",
    (DS.DEMO.value, DS.NICK.value, DS.UPLOAD.value),
    index=0,
)


log_file_path = logfile = path_df_us_fips_csv = None
use_demo_data = False
if DS(data_source) is DS.UPLOAD:
    logfile = st.file_uploader(
        "Choose an ssh log file to analyze (e.g., /var/log/auth.log)",
        accept_multiple_files=False,
    )

    # need to convert to StringIO so it works like an opened file elsewhere
    if logfile:
        logfile = StringIO(logfile.getvalue().decode("utf-8"))

    # still need to load df_us path so you can save processed FIPS codes later
    _, path_df_us_fips_csv = get_data_paths(
        data_dir=Path("./data"), use_demo_data=use_demo_data
    )

else:

    if DS(data_source) is DS.DEMO:
        use_demo_data = True
    elif DS(data_source) is DS.NICK:
        use_demo_data = False

    log_file_path, path_df_us_fips_csv = get_data_paths(
        data_dir=Path("./data"), use_demo_data=use_demo_data
    )

if st.button("Load Data"):
    st.session_state.data = get_data(logfile, log_file_path)

if "data" in st.session_state:
    with st.expander("US County Lookup"):
        st.markdown(
            "*Since the most attacks came from US, you may want to better understand where in the US attacks are coming from. Getting FIPS codes from lat/lon requires the [FCC Census API](https://geo.fcc.gov/api/census/), which can take a ***very*** long time to process thousands of IP-lookup requests. Thus, you may want to cache things - this has already been done for the included datasets.*"
        )

        # if using your own data, you'll need to compute the FIPS data each time, so don't even give the option
        US_fips_data_source = US_FIPS_Source.FCC_API

        cant_use_cached_US_FIPS = DS(data_source) is DS.UPLOAD
        if st.checkbox(
            "Use cached FIPS codes (o/w FCC API is SLOW)",
            value=not cant_use_cached_US_FIPS,
            disabled=cant_use_cached_US_FIPS,
        ):
            US_fips_data_source = US_FIPS_Source.CSV

        if st.button("Get US FIPS Data"):
            st.session_state.data_US_FIPS = get_data_US_FIPS(
                st.session_state.data, path_df_us_fips_csv, US_fips_data_source
            )

            st.download_button(
                label="Save Log Dataframe w/ FIPS Data",
                data=convert_df(st.session_state.data_US_FIPS),
                file_name=path_df_us_fips_csv.name,
                mime="text/csv",
            )

    # need to make a copy because AgGrid very cooly modifies the underlying data (including type casting) - SMH
    my_AgGrid(st.session_state.data.copy())
