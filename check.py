#!/usr/bin/env python3

import subprocess

class Derive(object):
    
    def __init__(self, output, inputDrvs, inputSrcs, system, builder, args, envVars):
        self.output = output
        self.inputDrvs = inputDrvs
        self.inputSrcs = inputSrcs
        self.system = system
        self.builder = builder
        self.args = args
        self.envVars = dict(envVars)

    @property
    def name(self):
        # XXX this is not generally valid. 
        return self.envVars['name'].split('-')[0]

derivations = []
for d in subprocess.check_output(['nix-store', '--gc', '--print-live']).decode('ascii').split('\n'):
    if not d.endswith('.drv'):
        continue
    d_src = open(d, 'r').read()
    derivations.append(eval(d_src))

class Vulnerability(object):

    cve_id = None
    product_names = ()

    def __init__(self):
        self.product_names = set()

    @staticmethod
    def fromNode(node):
        vuln = Vulnerability()
        vuln.cve_id = node.get('id')
        for product in node.findall('.//vuln:product', NS):
            name = product.text.split(':')[3]
            vuln.product_names.add(name)
        return vuln

    def check_installed(self):
        for d in derivations:
            if d.name in self.product_names:
                return True

import xml.etree.ElementTree as ET
NS = {'': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
      'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4'}

vulnerabilities = []

def parse_db(filename):
  tree = ET.parse(filename)
  root = tree.getroot()
  for node in root:
      vx = Vulnerability.fromNode(node)
      vulnerabilities.append(vx)

parse_db('nvdcve-2.0-2016.xml')
parse_db('nvdcve-2.0-2015.xml')


for vx in vulnerabilities:
    if vx.check_installed():
        print(vx.cve_id)
        print(vx.product_names)
