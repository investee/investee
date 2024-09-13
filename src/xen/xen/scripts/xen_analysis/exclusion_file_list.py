#!/usr/bin/env python3

import os, glob, json
from . import settings

class ExclusionFileListError(Exception):
    pass


def __cppcheck_path_exclude_syntax(path):
    # Prepending * to the relative path to match every path where the Xen
    # codebase could be
    path = "*" + path

    return path


# Reads the exclusion file list and returns a list of relative path to be
# excluded.
def load_exclusion_file_list(input_file):
    ret = []
    try:
        with open(input_file, "rt") as handle:
            content = json.load(handle)
            entries = content['content']
    except json.JSONDecodeError as e:
        raise ExclusionFileListError(
                "JSON decoding error in file {}: {}".format(input_file, e)
        )
    except KeyError:
        raise ExclusionFileListError(
            "Malformed JSON file: content field not found!"
        )
    except Exception as e:
        raise ExclusionFileListError(
                "Can't open file {}: {}".format(input_file, e)
        )

    for entry in entries:
        try:
            path = entry['rel_path']
        except KeyError:
            raise ExclusionFileListError(
                "Malformed JSON entry: rel_path field not found!"
            )
        abs_path = settings.xen_dir + "/" + path
        check_path = [abs_path]

        # If the path contains wildcards, solve them
        if '*' in abs_path:
            check_path = glob.glob(abs_path)

        # Check that the path exists
        for filepath_object in check_path:
            if not os.path.exists(filepath_object):
                raise ExclusionFileListError(
                    "Malformed path: {} refers to {} that does not exists"
                    .format(path, filepath_object)
                )

        if settings.analysis_tool == "cppcheck":
            path = __cppcheck_path_exclude_syntax(path)
        else:
            raise ExclusionFileListError(
                "Unimplemented for {}!".format(settings.analysis_tool)
            )

        ret.append(path)

    return ret
