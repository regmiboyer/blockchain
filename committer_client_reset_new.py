#########################################################################
# Copyright 2020 VMware, Inc.  All rights reserved. -- VMware Confidential
#########################################################################
# CLI version (standalone) of utility to monitor the health of replicas and
# also run periodic tests to verify health & availability of blockchain nodes
# When a crash is detected (replica status or transaction verification failure),
# support logs are collected from all the supplied replicas
#
# Example: python3 monitor_replicas.py
#  --replicas daml_committer:10.70.30.226,10.70.30.225,10.70.30.227,10.70.30.228
#  --replicas daml_participant:10.70.30.229
#  --loadInterval 1
import argparse
import cryptography
import json
import logging
import os
import paramiko
import subprocess
import sys
import tempfile
import time
import warnings
CONCORD_USERNAME = "root"
CONCORD_PASSWORD = "c0nc0rd"
BLOCKCHAIN_CONTAINERS = {
    "daml_committer": [
        "agent",
        "fluentd",
        "concord",
        "daml_execution_engine"
    ],
    "daml_participant": [
        "agent",
        "fluentd",
        "daml_ledger_api",
        "daml_index_db",
    ]
}
KILL_NODE = [
    "docker ps -a -q | xargs docker rm -f",
    "docker network disconnect --force blockchain-fabric concord",
    "docker network rm blockchain-fabric",
    "rm -rf /config/concord/cores",
    "rm -rf /config/concord/rocksdbdata",
    "rm -rf /config/daml_index_db",
    "df -h"
]
START_NODE = [
    "docker run -d --name=agent --restart=always -v /config:/config -v /var/run/docker.sock:/var/run/docker.sock -p 8546:8546 vmware-docker-blockchainsaas.bintray.io/vmwblockchain/agent:0.6.0.1115"
]
def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--replicas", action='append', nargs='*',
                        help="repeated set of blockchain type:<comma separated list of IPs>")
    args = parser.parse_args()
    all_replicas = {}
    for item in args.replicas:
        blockchain_type, ips = item[0].split(':')
        all_replicas[blockchain_type] = ips.split(',')
    log.info("Reset blockchain type/replicas: {}".format(
        json.dumps(all_replicas, sort_keys=True, indent=4)))
    log.info("")
    log.info("************************************************************")
    reset_blockchain(all_replicas)
def ssh_connect(host, username, password, command, log_mode=None):
    '''
    Helper method to execute a command on a host via SSH
    :param host: IP of the destination host
    :param username: username for SSH connection
    :param password: password for username
    :param command: command to be executed on the remote host
    :param log_mode: Override to log connectivity issue as a warning
    :return: Output of the command
    '''
    warnings.simplefilter("ignore", cryptography.utils.CryptographyDeprecationWarning)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    resp = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command,
                                                             get_pty=True)
        outlines = ssh_stdout.readlines()
        resp = ''.join(outlines)
        log.debug(resp)
    except paramiko.AuthenticationException as e:
        log.error("Authentication failed when connecting to {}".format(host))
    except Exception as e:
        if log_mode == "WARNING":
            log.warning("Could not connect to {}".format(host))
        else:
            log.error("Could not connect to {}: {}".format(host, e))
    return resp
def reset_blockchain(replicas):
    for blockchain_type, replica_ips in replicas.items():
        log.info("Verifying health on {} ({})".format(replica_ips, blockchain_type))
        for replica_ip in replica_ips:
            log.info("{}...".format(replica_ip))
            for command_to_run in KILL_NODE:
                # command_to_run = "docker ps --format '{{.Names}}'"
                ssh_output = ssh_connect(replica_ip, CONCORD_USERNAME, CONCORD_PASSWORD, command_to_run)
                log.info("SSH output: {}".format(ssh_output))
        for replica_ip in replica_ips:
            log.info("{}...".format(replica_ip))
            for command_to_run in START_NODE:
                # command_to_run = "docker ps --format '{{.Names}}'"
                ssh_output = ssh_connect(replica_ip, CONCORD_USERNAME, CONCORD_PASSWORD, command_to_run)
                log.info("SSH output: {}".format(ssh_output))
    return True
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)
    main(sys.argv)