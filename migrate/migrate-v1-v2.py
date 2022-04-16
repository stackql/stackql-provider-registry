import os
import yaml


def resource_change(r :dict) -> dict:
  enc_str = r['path']['$ref'].replace('/', '~1')
  op_str = r['operation']['$ref']
  r['operation']['$ref'] = f'#/paths/{enc_str}/{op_str}'
  del r['path'] 
  return r


def mutate_doc(doc :dict) -> dict:
  if not doc.get('components', {'x-stackQL-resources': None}).get('x-stackQL-resources'):
    return doc
  for k, v in doc.get('components').get('x-stackQL-resources').items():
    for mk, m in v.get('methods').items():
      print(f'processing method = {mk}')
      doc['components']['x-stackQL-resources'][k]['methods'][mk] = resource_change(m)
  return doc

def mutate_rsc_only_doc(doc :dict) -> dict:
  if not doc.get('resources'):
    return doc
  for k, v in doc.get('resources').items():
    for mk, m in v.get('methods').items():
      print(f'processing method = {mk}')
      doc['resources'][k]['methods'][mk] = resource_change(m)
  return doc

def mutate_all(root_path :str):
  for root, dirz, filez in os.walk(root_path):
    # for dir in dirz:
    #   mutate_all(os.path.join(root, dir))
    for fi in filez:
      if fi.endswith('.yaml'):
        print(f'processing file: "{os.path.join(root, fi)}"')
        with open(os.path.join(root, fi), 'r') as fr:
          doc = yaml.safe_load(fr)
        dm = mutate_rsc_only_doc(doc)
        with open(os.path.join(root, fi), 'w') as fw:
          yaml.dump(dm, fw)


def main():
  mutate_all('/Users/admin/stackql/stackql-provider-registry/providers/src/googleapis.com/v1/resources')


if __name__ == '__main__':
  main()