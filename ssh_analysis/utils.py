import numpy as np


def safe_attr_get(obj, attr):
    try:
        return getattr(obj, attr)
    except AttributeError:
        return None


def safe_dict_get(d, *keys, type=None):
    for key in keys:
        try:
            if d is not None:
                d = d[key]
            else:
                return None
        except KeyError:
            return None

    if type:
        return type(d)
    else:
        return d


def update_progress_bar(
    progress_bar,
    status_text,
    i: int,
    num_lines: int,
    update_every_x_percent: float = 1.0,
):

    if (progress_bar is None) or (status_text is None):
        return

    percent_complete = int(i / num_lines * 100)
    update_at_these_indices = list(
        np.floor(np.linspace(0, num_lines, int(100 / update_every_x_percent)))
    )

    if i in update_at_these_indices:
        progress_bar.progress(percent_complete)
        status_text.text(f"Processing Log File: {percent_complete:.0f}% Complete")
