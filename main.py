#!/bin/python3 -u

import sys
import json
import struct
import gnupg

def get_message():
  raw_length = sys.stdin.buffer.read(4)
  
  if not raw_length:
    sys.exit(0)
    
  message_length, = struct.unpack('=I', raw_length)
  message = sys.stdin.buffer.read(message_length)
  
  return json.loads(message)

def encode_message(type_text, message_content):
  encoded_content = json.dumps({ 'type': type_text, 'data': message_content })
  encoded_length = struct.pack('=I', len(encoded_content))
  
  return encoded_length, encoded_content

def send_message(encoded_message):
  sys.stdout.buffer.write(encoded_message[0])
  sys.stdout.buffer.flush()
  sys.stdout.write(encoded_message[1])
  sys.stdout.flush()

MARSHAL_MAP = {
  gnupg.ListKeys: lambda x: list(x),
  gnupg.Crypt: lambda x: x.status and x.data.decode('ascii'),
  gnupg.Sign: lambda x: x.status and x.data.decode('ascii'),
  gnupg.Verify: lambda x: x.status and { 'keyid': x.key_id, 'valid': x.valid, 'key_status': x.key_status },
  str: lambda x: x
}

if __name__ == '__main__':
  # use default keyring
  gpg = gnupg.GPG()
  message = get_message()
  
  # whitelist of gpg attributes plz.
  # TODO: verify_data ???
  action_whitelist = ('list_keys', 'sign', 'verify', 'encrypt', 'decrypt', 'export_keys')
  
  if not message['action'] in action_whitelist:
    send_message(encode_message('error', 'forbidden action'))
    sys.exit(-1)
    
  with open('request.log', 'a') as fh:
    fh.write(json.dumps(message))
    fh.write('\n\n')
  
  try:
    result = getattr(gpg, message['action'])(*message['args'], **message['kwargs'])
    result_type = type(result)
    marshal_fn = MARSHAL_MAP[result_type]
    marshalled_result = marshal_fn(result)
    
    if marshalled_result:
      status = 'success'
    else:
      status = 'error'
      marshalled_result = 'error: ' + message['action']
      
    send_message(encode_message(status, marshalled_result))
  except Exception as e:
    send_message(encode_message('error', e))
    sys.exit(-1)
