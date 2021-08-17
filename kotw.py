#!/usr/bin/python3
# Ugly python script that turns a trustedqsl key file into an ssh public keypair

import sys
from subprocess import check_output as ck 

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    print("     kotr.py - Keyring of the World     ")
    print("=====------------------------------=====")
    print("Requires path to tqsl key file as input.")
    print("Example: kotr.py ~/.tqsl/keys/KA1DS")
    exit()

pvs_start = "-----BEGIN PRIVATE KEY-----"
pvs_end = "-----END PRIVATE KEY-----"
pbs_start = "-----BEGIN PUBLIC KEY-----"
pbs_end = "-----END PUBLIC KEY-----"

with open(filename, mode='r') as rl:
    rawl = rl.readlines()
with open(filename, mode='r') as rs:
    raws = rs.read()
raw_entries = raws.split("<eor>")
del_entries = []
del_entry = 0
for i in raw_entries:
    if "<DELETED:4>True" in i:
        del_entries.append(del_entry)
    del_entry += 1
for i in del_entries:
    del raw_entries[i]
del_entries = []
del_entry = 0
for i in raw_entries:
    if i == "\n\n":
        del_entries.append(del_entry)
    del_entry += 1
for i in del_entries:
     del raw_entries[i]
if len(raw_entries) > 1:
    print(f"WARNING - MULTIPLE VALID ENTRIES EXIST: {len(raw_entries)}")
crt = raw_entries[0]

callsign_raw = crt.split("CALLSIGN:")
callsign_bsnip = callsign_raw[1].split("\n\n<")
callsign_tsnip = callsign_bsnip[0].split(">")
callsign = callsign_tsnip[1]

pvkl = crt.split(pvs_end)
pvkh = pvkl[0].split(pvs_start)[1]
pvk = pvs_start + pvkh + pvs_end + '\n'

pbkl = crt.split(pbs_end)
pbkh = pbkl[0].split(pbs_start)[1]
pbk = pbs_start + pbkh + pbs_end + '\n'

privfile = open(f"./{callsign}.id_rsa", "x")
privfile.write(pvk + pbk)
privfile.close()
print(f"Private key {callsign}.id_rsa created.")
pubkey_string = ck(['ssh-keygen', '-i', '-m', 'PKCS8', '-f', f'{callsign}.id_rsa'])
pubfile = open(f"./{callsign}.id_rsa.pub", "xb")
pubfile.write(pubkey_string)
pubfile.close()	
print(f"Public key {callsign}.id_rsa.pub generated.")


