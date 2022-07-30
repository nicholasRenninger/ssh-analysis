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
