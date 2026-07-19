# COV-5: zip-slip (CWE-22). An archive entry name is attacker-controlled; a
# crafted entry like "../../etc/cron.d/x" escapes the extraction directory when
# joined to the destination and written without containment.
import os
import zipfile


def extract(archive, dest_dir):
    z = zipfile.ZipFile(archive)
    for name in z.namelist():
        dest = os.path.join(dest_dir, name)  # entry name flows into the path
        with open(dest, "wb") as out:         # zip-slip sink
            out.write(z.read(name))
