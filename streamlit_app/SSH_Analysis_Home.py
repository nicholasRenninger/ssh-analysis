import streamlit as st

st.set_page_config(page_title="Landing Page", page_icon="🏠", layout="wide")

st.write("# SSH Log Analysis")

st.sidebar.success("Select a page above.")

st.markdown(
    """
    I wanted a way to quickly analyze my SSH access logs, as I saw quite a bit of traffic. Inspired by [this](https://bastian.rieck.me/blog/posts/2019/ssh_incidents/) (with [this underyling GH repo](https://github.com/Pseudomanifold/Auceps)) and [this](https://gist.github.com/ryupold/eaedea845d4b54f10d68c9e97f48c65b), I made some more tools to use in [a notebook](https://github.com/nicholasRenninger/ssh-analysis/blob/main/ssh_analysis/auth_log_analysis.ipynb), and then moved them into this app.

    [My GitHub repo](https://github.com/nicholasRenninger/ssh-analysis) contains the data and code powering this app!

    *Logs are read into a [Protobuf](https://developers.google.com/protocol-buffers/docs/overview) [object (`SSHLogs`)](https://github.com/nicholasRenninger/ssh-analysis/blob/main/ssh_analysis/ssh_log.proto), with each IP address being sent to a GeoIP DB and returned metadata stored as `IPLookupData` in each `SSHLog` (each `SSHLog` is stored as an element of `SSHLogs`). This `SSHLogs` object is transformed into a dataframe for more analysis.*
    """
)
