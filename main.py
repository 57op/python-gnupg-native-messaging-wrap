#!/bin/python3 -u

import sys
import json
import struct
import gnupg

from gpge import GPGe

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

# schema/pattern matching
def list_schema_match(schema, instance):
  if len(schema) != len(instance):
    return False

  for s, i in zip(schema, instance):
    if not schema_match(s, i):
      return False

  return True

def dict_schema_match(schema, instance):
  for prop, s in schema.items():
    i = instance.get(prop)

    if i is None or not schema_match(s, i):
      return False

  return len(schema.items()) == len(instance.items())

def schema_match(schema, instance):
  if schema != instance:
    # schema is primitive type, so schema must be instance
    if schema is None or isinstance(schema, (bool, int, float, str)):
      return False
    # both are list, recursion
    elif isinstance(schema, (list, tuple)) and isinstance(instance, (list, tuple)):
      if not list_schema_match(schema, instance):
        return False
    # both are dict, recursion
    elif isinstance(schema, dict) and isinstance(instance, dict):
      if not dict_schema_match(schema, instance):
        return False
    # instance must be an instance of schema
    elif not isinstance(instance, schema):
      return False

  return True

def is_valid_message(message, action_whitelist):
  args_dict = action_whitelist.get(message['action'])

  if not args_dict:
    return False

  message_copy = message.copy()
  del message_copy['action']

  return dict_schema_match(args_dict, message_copy)

# allowed actions and arguments.
ACTION_WHITELIST = {
  'get_version': {
    'args': [],
    'kwargs': {}
  },
  'list_keys': {
    'args': [bool],
    'kwargs': {
      'sigs': bool,
      'keys': list
    }
  },
  'sign': {
    'args': [str],
    'kwargs': {
      'keyid': str,
      'clearsign': False,
      'binary': False,
      'detach': True
    }
  },
  'verify_data_streams': {
    'args': [str, str],
    'kwargs': {}
  },
  'encrypt': {
    'args': [str, str],
    'kwargs': {
      'armor': True
    }
  },
  'decrypt': {
    'args': [str],
    'kwargs': {}
  },
  'export_keys': {
    'args': [str], # second argument is private, which is not allowed to export.
    'kwargs': {
      'minimal': bool,
      'armor': True
    }
  }
}

# TODO: improve marshalling strategy
MARSHAL_MAP = {
  gnupg.ListKeys: lambda x: list(x),
  gnupg.Crypt: lambda x: x.status and { 'data': x.data.decode('ascii'), 'ok': x.ok, 'valid': x.valid, 'sig_info': x.sig_info },
  gnupg.Sign: lambda x: x.status and x.data.decode('ascii'),
  gnupg.Verify: lambda x: x.valid and { 'keyid': x.key_id, 'key_status': x.key_status },
  str: lambda x: x, # export_keys
  tuple: lambda x: list(x) # version
}

if __name__ == '__main__':
  # use default keyring
  gpg = GPGe()
  message = get_message()

  if not is_valid_message(message, ACTION_WHITELIST):
    send_message(encode_message('error', f'forbidden action {message}'))
    sys.exit(-1)

  with open('request.log', 'a') as fh:
    fh.write(json.dumps(message))
    fh.write('\n')

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

    #with open('request.log', 'a') as fh:
    #  fh.write(json.dumps(marshalled_result))
    #  fh.write('\n\n')
  except Exception as e:
    send_message(encode_message('error', e))
    sys.exit(-1)
