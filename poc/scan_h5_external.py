import sys

import h5py


def scan(path):
    findings = []

    def visit(name, obj):
        if isinstance(obj, h5py.Dataset):
            if obj.external:
                findings.append("%s: external storage %s" % (name, obj.external))
            if obj.is_virtual:
                findings.append("%s: virtual dataset" % name)

    with h5py.File(path, "r") as f:
        f.visititems(visit)
    return findings


if __name__ == "__main__":
    bad = scan(sys.argv[1])
    for line in bad:
        print("SUSPICIOUS", line)
    sys.exit(1 if bad else 0)
