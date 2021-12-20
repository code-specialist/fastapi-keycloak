import os.path
import pathlib

import mkdocs.config.config_options
import mkdocs.plugins
import mkdocs.structure.files


class SameDirPlugin(mkdocs.plugins.BasePlugin):
    def __init__(self):
        # HACK: Before the code has a chance to kick in, remove the validation of directory paths,
        # so mkdocs doesn't refuse to process docs alongside mkdocs.yml.
        mkdocs.config.config_options.Dir.post_validation = _replace_validation

    def on_files(self, files, config):
        result = []
        for f in files:
            # Exclude everything under site_dir.
            if _is_path_under(base=config["site_dir"], path=f.abs_src_path):
                continue
            # Exclude non-document pages in the root of docs_dir.
            if (
                len(pathlib.Path(f.src_path).parts) > 1
                or f.is_documentation_page()
                or f.is_javascript()
                or f.is_css()
                or f.name == "CNAME"
            ):
                result.append(f)

        return mkdocs.structure.files.Files(result)


def _replace_validation(self, config, *args, **kwargs):
    # HACK: Also make so it doesn't realize we're using a subdirectory for the site dir and such.
    config["docs_dir"] = os.path.join(config["docs_dir"], ".")


def _is_path_under(base, path):
    try:
        pathlib.Path(path).relative_to(base)
        return True
    except ValueError:
        return False
