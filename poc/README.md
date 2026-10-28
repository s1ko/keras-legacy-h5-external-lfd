# PoC files

| File | Purpose |
|---|---|
| `poc_lfd_legacy_h5.py` | Builds a one-layer model, writes `keras_lfd_poc.h5` in which `dense/bias:0` is an HDF5 dataset backed by `external=[('/etc/hostname', 0, 32)]`, calls `keras.saving.load_weights`, and compares the layer bias bytes with the first 32 bytes of the target file. Needs Python 3.12 or later (an f-string contains a backslash escape). |
| `keras_lfd_poc.h5` | The file written by the script (8224 bytes). It stores only the external file name, not the file contents. |
| `exploit_loadmodel.py` | Same idea through `keras.models.load_model('attacker_full.h5', compile=False, safe_mode=True)`, with a full-model layout (`model_config` plus `model_weights`). |
| `scan_h5_external.py` | `h5py`-based check that lists datasets with external storage or a virtual layout. |

Environment of the original run: Debian, `keras` reported as 3.15.0 (see the README for what that version string means), `tensorflow 2.21.0`.

```bash
pip install 'keras==3.14.0' h5py numpy tensorflow
python poc_lfd_legacy_h5.py
python exploit_loadmodel.py
python scan_h5_external.py keras_lfd_poc.h5
```

Change `TARGET` in the scripts to any readable file. The leaked bytes land in the first `NBYTES` of the bias vector as little-endian float32 values; `bias.view(np.uint8).tobytes()` recovers them.
