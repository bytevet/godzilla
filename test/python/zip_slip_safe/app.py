# FP guard for zip-slip: the entry name is sanitized with
# werkzeug.utils.secure_filename, which strips "../" and path separators to a
# safe basename before it reaches the filesystem, so no traversal is possible.
import os
import zipfile

from werkzeug.utils import secure_filename


def extract(archive, dest_dir):
    z = zipfile.ZipFile(archive)
    for name in z.namelist():
        safe = secure_filename(name)          # sanitizer: collapses to a basename
        dest = os.path.join(dest_dir, safe)
        with open(dest, "wb") as out:
            out.write(z.read(name))
