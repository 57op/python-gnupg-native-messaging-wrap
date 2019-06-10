from tempfile import NamedTemporaryFile
from gnupg import GPG

class GPGe(GPG):
  def __init__(self, **kwargs):
    super().__init__(**kwargs)

  def verify_data_streams(self, signature, data, temp_dir=None):
    if not isinstance(signature, bytes):
      # assume ascii signature
      signature = signature.encode('ascii')

    if not isinstance(data, bytes):
      data = data.encode('raw_unicode_escape')

    with NamedTemporaryFile(mode='wb+', dir=temp_dir, delete=True) as fh:
      fh.write(signature)
      fh.seek(0)
      return self.verify_data(fh.name, data)

  # todo: get_key (by keyid)