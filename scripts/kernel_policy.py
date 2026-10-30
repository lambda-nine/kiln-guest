#!/usr/bin/env python3
"""Enforce the guest kernel's required values and forbidden interfaces."""
import argparse
import json
from pathlib import Path
import re

POLICY = Path(__file__).resolve().parents[1]/'config/security-policy.json'

def validate(config, policy=POLICY):
    rules = json.loads(Path(policy).read_text())
    if rules['schema'] != 1:
        raise ValueError('unknown kernel policy schema')
    values = dict(re.findall(r'^CONFIG_(\w+)=(.+)$', Path(config).read_text(), re.M))
    errors = [f'{name}: require {value}, got {values.get(name, "n")}'
              for name, value in rules['required'].items() if values.get(name) != value]
    errors += [f'{name}: forbidden, got {values[name]}' for name in rules['forbidden']
               if values.get(name, 'n') != 'n']
    if errors:
        raise ValueError('kernel security policy: ' + '; '.join(errors))
    return {'required': len(rules['required']), 'forbidden': len(rules['forbidden']), 'passed': True}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('config', type=Path)
    a = p.parse_args()
    print(json.dumps(validate(a.config), sort_keys=True))
