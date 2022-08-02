# Simple SSH Analysis

I wanted a way to quickly analyze my SSH access logs, as I saw quite a bit of traffic. Inspired by [this](https://bastian.rieck.me/blog/posts/2019/ssh_incidents/) (with [this underyling GH repo](https://github.com/Pseudomanifold/Auceps)) and [this](https://gist.github.com/ryupold/eaedea845d4b54f10d68c9e97f48c65b), **I made some more tools to use in a notebook and turned them into a [streamlit app](https://nicholasrenninger-ssh-ana-streamlit-appssh-analysis-home-qp3ied.streamlitapp.com/).**

## About
Logs are read into a [Protobuf](https://developers.google.com/protocol-buffers/docs/overview) [object (`SSHLogs`)](https://github.com/nicholasRenninger/ssh-analysis/blob/main/ssh_analysis/ssh_log.proto), with each IP address being sent to a GeoIP DB and returned metadata stored as `IPLookupData` in each `SSHLog` (each `SSHLog` is stored as an element of `SSHLogs`). This `SSHLogs` object is transformed into a dataframe for more analysis.

Metadata associated with an IP address can be queried from online geo-coding services or from geolite2 DBs. This project uses [an older, self-contained geolite2 package](https://pythonhosted.org/python-geoip/). You could easily modify this example to use a more accurate geoIP DB by modifying this function that maps an IP address to an `IPLookupData` object.

Since the most attacks came from US, you may want to better understand where in the US attacks are coming from. Getting FIPS codes from lat/lon requires the [FCC Census API](https://geo.fcc.gov/api/census/), which can take a *very* long time to process thousands of IP-lookup requests. Thus, you may want to cache things - this has already been done for the included datasets (`data/*df_us.csv`).

## Install

I use [poetry](https://python-poetry.org/) for dep management and install. You can install it easily by [following these intstructions](https://python-poetry.org/docs/#installation). 
- ***If you plan to use VS Code for running jupyter notebooks** you will [need set the venv location](https://stackoverflow.com/a/64434542) to the project directory to make it easy for VS Code to find the venv.*
- ***If you plan to use Jupyter for running jupyter notebooks**, [follow this guide](https://deckgl.readthedocs.io/en/latest/installation.html#enabling-pydeck-for-jupyter) if you want to be able to run the `pyDeck` visualizations.*


Once you have poetry installed and on your path, install via:
```bash
git clone  ~/git/ssh_analysis
cd ~/git/ssh_analysis
# ONLY IF USING VS Code - changing where venvs are stored for VSCode
poetry config virtualenvs.in-project true
poetry install
```

If you wish to re-compile the python protobuf definitions, you will also need to install the protobuf compiler

## Prepping data

Before you can run the analysis, you need to prep your SSH log data. You can do this via:

```bash
ll /var/log/auth.*
sudo gzip -d /var/log/auth.log.*.gz
sudo cat /var/log/auth.* > ~/Desktop/my_auth.log
```

You should now have all of your `/var/log/auth.log` concatenated into one file, `~/Desktop/my_auth.log`. You should now move this file to the root of the `ssh_analysis` directory. Assuming you cloned `ssh_analysis` to `~/git`:

```bash
mv ~/Desktop/my_auth.log ~/git/ssh_analysis/data/my_auth.log
```

## Running the streamlit app

The package powers a streamlit app which can be easily run via:

```bash
streamlit run streamlit_app/SSH_Analysis_Home.py
```

## Running analysis

To run the example, all you need to do is open the notebook `./ssh_analysis/auth_log_analysis.ipynb` and run it with the python kernel you installed earlier. This can be done easily with Jupyter Lab or VS Code.

```bash
cd ~/git/ssh_analysis
poetry shell
jupyter lab
```