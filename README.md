# Keras: legacy `.h5` loader follows HDF5 external storage (local file disclosure)

The legacy HDF5 weight loader in Keras (`keras/src/legacy/saving/legacy_h5_format.py`) reads each weight with `np.asarray(f[weight_name])` and never checks whether the dataset is backed by HDF5 external storage. A crafted `.h5` file whose dataset is declared as `external=[(path, offset, nbytes)]` makes the loader read `nbytes` of an arbitrary local file into the model's weights when the victim calls `keras.saving.load_weights(model, "x.h5")` or `keras.models.load_model("x.h5")`. The bytes are then observable through inference, `get_weights()`, or by re-saving and sharing the model. `safe_mode=True` has no effect on this path.

The modern `.weights.h5` / `.keras` loader had been fixed for external storage in January 2026 (CVE-2026-1669). This is the same behaviour on the legacy loader, fixed upstream on 2026-04-30.

| | |
|---|---|
| CVE | None claimed. See [Prior coverage](#prior-coverage). |
| CWE | CWE-200 Exposure of Sensitive Information; CWE-73 External Control of File Name or Path |
| Project | [keras-team/keras](https://github.com/keras-team/keras) |
| Affected | Source-checked at `v3.3.3`, `v3.5.0`, `v3.9.0`, `v3.11.3`, `v3.12.0`, `v3.12.1`, `v3.13.0`, `v3.13.2`, `v3.14.0` and `master` as of 2026-04-25; the releases between them were not individually fetched. Earlier 3.x releases were not checked. |
| Fixed in | Commit `d5a88bdb137c0d3039b8f4bbbe8c7099925cc10c` ([#22801](https://github.com/keras-team/keras/pull/22801), merged 2026-04-30). First release containing it on the 3.14 line: `v3.14.1` (2026-05-07). The guard is also present in `v3.12.2` (2026-05-07), `v3.15.0` and `v3.15.1`. There is no 3.13.x release with the fix. |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = 5.5 (Medium) |
| Reported by | s1ko ([github.com/s1ko](https://github.com/s1ko), `s1ko@riseup.net`) |

## Scope, stated plainly

- The victim must load an attacker-supplied legacy `.h5` file. The target file must exist and be readable by the process, and the disclosed bytes reach the attacker only if the victim then exposes them (model output, `get_weights()`, a re-saved model that is shared or uploaded). Vector `AV:L` reflects the file-borne delivery; a service that loads uploaded `.h5` files and returns predictions or the re-saved model is exposed remotely.
- Only the first `nbytes` declared in the file are read, and the dataset dtype/shape must be consistent with them. Files are read as raw bytes into float tensors.
- Version statement for the original test. The report to Huntr says it was tested on "keras 3.15.0". No such release existed on 2026-04-26: `v3.14.0` was published on 2026-04-03 and `v3.15.0` on 2026-06-24. On `master` as of 2026-04-25 (`8f5a00c30f8f`), `keras/src/version.py` already read `"3.15.0"`, so the result most likely came from a development checkout of `master`. Which commit was installed is not recorded. UNVERIFIED. What was checked directly: the vulnerable line is present, unchanged, in both `v3.14.0` (line 582) and `master` at `8f5a00c30f8f` (line 582). A run of the PoC against the released `3.14.0` wheel was not repeated for this write-up. UNVERIFIED at runtime.
- The statement in the original report that "even on Keras 3.15.0 ... the legacy path remains open" is not correct for the released 3.15.0, which contains the fix. It described pre-fix `master`.
- The upstream fix was merged four days after this report was filed. This repository does not claim that the change was made because of the report.

## Threat model

Attacker publishes or sends a `.h5` model or weights file (model hub, shared drive, bug report attachment, CI artifact). The victim loads it with `keras.saving.load_weights`, `Model.load_weights` or `keras.models.load_model` on an `.h5`/`.hdf5` path. The file declares one or more datasets with HDF5 external storage pointing at a path the victim can read (for example SSH keys or cloud credentials in the victim's home directory, `/etc/*`, application `.env` files). HDF5 itself performs the file read.

## Execution

### Root cause

Excerpts are from `v3.14.0`, `keras/src/legacy/saving/legacy_h5_format.py`.

Line 568-582:

```python
def load_subset_weights_from_hdf5_group(f):
    """Load layer weights of a model from hdf5.
    ...
    weight_names = load_attributes_from_hdf5_group(f, "weight_names")
    return [np.asarray(f[weight_name]) for weight_name in weight_names]
```

It is called from `load_weights_from_hdf5_group` (lines 377 and 400-401) and `load_weights_from_hdf5_group_by_name` (lines 505 and 537-538). `load_model_from_hdf5` reaches it at line 142: `load_weights_from_hdf5_group(f["model_weights"], model)`. The optimizer weights loader at lines 585-600 also returns raw `weights_group[weight_name]` datasets.

Routing, `keras/src/saving/saving_api.py` at `v3.14.0`: `load_model` sends `.h5`/`.hdf5` paths to `legacy_h5_format.load_model_from_hdf5` (line 195) and `load_weights` sends them to the `load_weights_from_hdf5_group*` functions (lines 300-319).

For comparison, the modern path in `keras/src/saving/saving_lib.py` already had `H5IOStore._verify_dataset`, which rejects `dataset.external`. The legacy module did not use it. Reading a dataset with `np.asarray` makes h5py/libhdf5 open and read the external file named in the dataset's creation properties.

### Fix upstream

Commit `d5a88bdb` ("Refactor and share H5 validation code between legacy and new format. (#22801)") routes the legacy loader through the shared helper `safe_get_h5_dataset` (and `safe_get_h5_group`). At `v3.14.1`:

```python
    dataset_type = group.get(name, default=None, getclass=True, getlink=True)
    if dataset_type in (h5py.ExternalLink, h5py.SoftLink):
        raise ValueError(f"Not allowed: H5 file with {dataset_type.__name__}")

    dataset = group[name]
    if not isinstance(dataset, h5py.Dataset):
        raise ValueError(
            f"Invalid H5 file, expected Dataset, received {type(dataset)}"
        )
    if dataset.external:
        raise ValueError(
            f"Not allowed: H5 file with external Dataset: {dataset.external}"
        )
    if dataset.is_virtual:
        raise ValueError("Not allowed: H5 file with virtual Dataset")
```

and `load_subset_weights_from_hdf5_group` becomes `np.asarray(safe_get_h5_dataset(group, weight_name))`.

### Reproduction

```bash
pip install 'keras==3.14.0' h5py numpy tensorflow
cd poc
python poc_lfd_legacy_h5.py
```

The script writes `keras_lfd_poc.h5`:

```python
with h5py.File('keras_lfd_poc.h5', 'w') as f:
    f.attrs['layer_names'] = [b'dense']
    f.attrs['keras_version'] = b'2.15.0'
    f.attrs['backend'] = b'tensorflow'
    g = f.create_group('dense')
    g.attrs['weight_names'] = [b'kernel:0', b'bias:0']
    g.create_dataset('kernel:0', data=np.zeros((1, UNITS), dtype='float32'))
    g.create_dataset('bias:0', shape=(UNITS,), dtype='float32',
                     external=[(TARGET, 0, NBYTES)])
```

then calls `keras.saving.load_weights(model, 'keras_lfd_poc.h5')` and reads `model.get_layer('dense').bias`.

Result recorded on 2026-04-26 (Debian, `tensorflow 2.21.0`, the `keras` development version discussed above): the first bytes of the bias vector equal the first bytes of `/etc/hostname` of the test host, and the script printed `Matches target file: True`. The value is omitted here. The same result was recorded with `poc/exploit_loadmodel.py` (`keras.models.load_model(..., safe_mode=True)`).

On a fixed version the load raises `ValueError: Not allowed: H5 file with external Dataset: [...]`. That outcome was read from the source, not executed here. UNVERIFIED at runtime.

## Detection

File-format check: open the candidate with `h5py` and list datasets whose `external` or `is_virtual` property is set. `poc/scan_h5_external.py` does this (the calls are those used by Keras's own `safe_get_h5_dataset`; the script was not run on this host, where `h5py` is not installed. UNVERIFIED):

```
$ python scan_h5_external.py keras_lfd_poc.h5
SUSPICIOUS dense/bias:0: external storage [('/etc/hostname', 0, 32)]
```

The external file name is stored in clear text inside the HDF5 file (the PoC contains the string `/etc/hostname` in an HDF5 local heap). A coarse triage rule for uploads, with false positives for any legitimate HDF5 file that stores such strings in attributes:

```yara
rule hdf5_with_sensitive_absolute_path
{
    strings:
        $sig = { 89 48 44 46 0D 0A 1A 0A }
        $heap = "HEAP"
        $p1 = "/etc/passwd"
        $p2 = "/etc/shadow"
        $p3 = "/etc/hostname"
        $p4 = "/.ssh/"
        $p5 = "/.aws/"
        $p6 = "/proc/self/"
    condition:
        $sig at 0 and $heap and any of ($p*)
}
```

The signature, `HEAP` and `/etc/hostname` conditions were confirmed against `keras_lfd_poc.h5` with a byte search; the rule itself was not run through a YARA engine or against a corpus. Do not rely on it as a gate; use the `h5py` check.

Runtime: with a fixed Keras, loading such a file raises `Not allowed: H5 file with external Dataset`; that message in a pipeline log marks an attempt. On an affected version, `strace -f -e trace=openat` on the loading process shows an `openat` of the external path during `load_weights`/`load_model`, which is the clearest host-side indicator (Sigma-style: a Python process that opens a `.h5` model and then opens `/etc/passwd`, `~/.ssh/*` or similar within the same second).

## Mitigation

- Upgrade to `keras>=3.14.1` (or `3.12.2` on the 3.12 line, or `3.15.0`+). Stay off `3.13.x`: no fixed 3.13 release exists.
- Do not load legacy `.h5`/`.hdf5` files from untrusted sources. Prefer `.keras` archives on a fixed version, or `safetensors` for weights.
- Where upgrading is not possible, run `poc/scan_h5_external.py` on every file before loading and refuse any finding; or load inside a container or sandbox that cannot read host secrets.
- Mapping: CWE-73 / CWE-200 (restrict file access to intended paths); ATT&CK M1048 Application Isolation and Sandboxing, M1022 Restrict File and Directory Permissions.

## Timeline

| Date (UTC) | Event |
|---|---|
| 2026-01-28 | Keras commit `8a37f9d` (#22057) rejects HDF5 external storage in the modern loader (CVE-2026-1669). |
| 2026-02-18 | CVE-2026-1669 published; its text notes that legacy HDF5 paths remain susceptible. |
| 2026-04-03 | `v3.14.0` released (vulnerable). |
| 2026-04-26 | Reported via huntr.com (report `18b97520-5938-4c30-9c05-d0335cfcfc8c`). No triage, validation or response from the platform as of 2026-10-28. |
| 2026-04-30 | Upstream commit `d5a88bdb` (#22801, hertschuh) merged; legacy loader now uses the shared validation helper. |
| 2026-05-07 | `v3.14.1` and `v3.12.2` released with the change. |
| 2026-06-24 | `v3.15.0` released. |
| 2026-07-01 | CVE-2026-12480 published, referencing commit `d5a88bdb` and a different Huntr report. |
| 2026-10-28 | This advisory published. |

## Prior coverage

- Fixed upstream by `d5a88bdb` (#22801) on 2026-04-30, four days after this report was filed. Nothing in the commit or PR refers to this report, and no credit is implied.
- [CVE-2026-1669](https://github.com/advisories/GHSA-3m4q-jmj6-r34q) (GHSA-3m4q-jmj6-r34q, published 2026-02-18, reporter N3mes1s): HDF5 external storage and external links during `load_weights`. Its fix covered the modern loader. Its description states "legacy HDF5 paths remain susceptible", so the legacy path was known to be exposed before this report.
- [CVE-2026-12480](https://github.com/advisories/GHSA-26c4-7vv6-867j) (GHSA-26c4-7vv6-867j, published 2026-07-01, no credits listed): described as virtual datasets (`is_virtual`) not being checked; references commit `d5a88bdb` and Huntr report `1875d257-5b03-4a69-ac70-e98653fa12c7`, a different submission. The change that fixes this issue is cited there, but the record concerns a different dataset property.
- [CVE-2026-9335](https://github.com/advisories/GHSA-m8wh-29wm-52mv) (GHSA-m8wh-29wm-52mv, published 2026-08-02): HDF5 `ExternalLink`/`SoftLink` handled by `keras.saving.load_weights` and `KerasFileEditor`; different construct.
- This repository describes an independent report, filed on 2026-04-26, of the `dataset.external` behaviour on the legacy loader. It claims none of the CVEs above.

## References

- Vulnerable line: [`legacy_h5_format.py` @ v3.14.0](https://github.com/keras-team/keras/blob/v3.14.0/keras/src/legacy/saving/legacy_h5_format.py#L568-L582)
- Fix: [`d5a88bdb`](https://github.com/keras-team/keras/commit/d5a88bdb137c0d3039b8f4bbbe8c7099925cc10c), PR [#22801](https://github.com/keras-team/keras/pull/22801)
- Earlier fix for the modern loader: [`8a37f9d`](https://github.com/keras-team/keras/commit/8a37f9dadd8e23fa4ee3f537eeb6413e75d12553), PR [#22057](https://github.com/keras-team/keras/pull/22057)
- [h5py: external datasets](https://docs.h5py.org/en/stable/high/dataset.html#external-datasets)
- [CWE-200](https://cwe.mitre.org/cgi-bin/jumpmenu.cgi?id=200), [CWE-73](https://cwe.mitre.org/cgi-bin/jumpmenu.cgi?id=73)

## License

MIT, see [LICENSE](LICENSE).
