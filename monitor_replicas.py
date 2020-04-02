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
 
DEFAULT_SUPPORT_LOGS_DEST="/var/log/blockchain_support"
CONCORD_USERNAME = "root"
CONCORD_PASSWORD = "c0nc0rd"
BLOCKCHAIN_CONTAINERS = {
   "daml_committer": [
      "agent",
      "fluentd",
      "concord",
      "daml_execution_engine",
#      "wavefront-proxy",
#     "jaeger-agent",
  #    "telegraf"
   ],
   "daml_participant": [
      "agent",
      "fluentd",
      "daml_ledger_api",
      "daml_index_db",
   #   "wavefront-proxy",
    #  "telegraf"
   ]
}
 
def main(args):
   parser = argparse.ArgumentParser()
   parser.add_argument("--replicas", action='append', nargs='*',
                       help="repeated set of blockchain type:<comma separated list of IPs>")
   parser.add_argument("--replicasConfig",
                      help="if replicas are not passed via --replicas, pass in replicas.json file via this option")
   parser.add_argument("--saveSupportLogsTo",
                       default="{}/logs_{}".format(DEFAULT_SUPPORT_LOGS_DEST,
                                                   time.strftime(
                                                      "%Y-%m-%d-%H-%M-%S",
                                                      time.gmtime())),
                       help="deployment support bundle archive path")
   parser.add_argument("--loadInterval",
                       type=int,
                       default=60,
                       help="Minutes to wait between monitors (default 60 mins)")
   args = parser.parse_args()
 
   if not args.replicasConfig and not args.replicas:
      log.error("Usage: pass either --replicas (or) --replicasConfig")
      sys.exit(1)
 
   if args.replicasConfig:
      with open(args.replicasConfig, "r") as fp:
         all_replicas = json.load(fp)
   else:
      all_replicas = {}
      for item in args.replicas:
         blockchain_type, ips = item[0].split(':')
         all_replicas[blockchain_type] = ips.split(',')
 
   for blockchain_type in BLOCKCHAIN_CONTAINERS.keys():
      if blockchain_type not in all_replicas.keys():
         log.error(
            "Missing args: --replicas daml_committer:<set of replicas> --replicas daml_participant:<set of replicas>")
         sys.exit(1)
 
   log.info("Monitoring blockchain type/replicas: {}".format(
      json.dumps(all_replicas, sort_keys=True, indent=4)))
   log.info("Load Interval: {} mins".format(args.loadInterval))
   log.info("Support bundle destination: {}".format(args.saveSupportLogsTo))
 
   log.info("")
   log.info("************************************************************")
   while True:
      start_time = time.time()
      if check_replica_health(all_replicas):
         log.info("All replicas are healthy")
      else:
         end_time = time.time()
         log.error("**** Blockchain nodes are not healthy after {} hrs".format((end_time-start_time)/3600))
 
         # Collect support logs for failed replica
         for blockchain_type, replica_ips in all_replicas.items():
            log.info(
               "Collect support bundle from all replica IPs: {}".format(
                  replica_ips))
            #create_concord_support_bundle(replica_ips, blockchain_type,
            #                             args.saveSupportLogsTo)
         return False
 
      log.info("Replica health will resume after {} mins...".format(args.loadInterval))
      time.sleep(args.loadInterval)
 
 
def execute_ext_command(command):
   '''
   Helper method to execute an external command
   :param command: command to be executed
   :return: True if command exit status is 0, else False
   '''
   log.debug("Executing external command: {}".format(command))
 
   completedProcess = subprocess.run(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
   try:
      completedProcess.check_returncode()
      log.debug("stdout: {}".format(
         completedProcess.stdout.decode().replace(os.linesep, "")))
      if completedProcess.stderr:
         log.info("stderr: {}".format(completedProcess.stderr))
   except subprocess.CalledProcessError as e:
      log.error(
         "Command '{}' failed to execute: {}".format(command, e.returncode))
      log.error("stdout: '{}', stderr: '{}'".format(completedProcess.stdout,
                                                    completedProcess.stderr))
      return False, completedProcess.stderr
 
   return True, completedProcess.stdout.decode().split("\n")
 
 
def create_concord_support_bundle(replicas, blockchain_type, test_log_dir):
   '''
   Helper method to create concord support bundle and upload to result dir
   :param replicas: List of IP addresses of concord nodes
   :param blockchain_type: Concord node type ("daml", "ethereum", etc)
   :param test_log_dir: Support bundle to be uploaded to
   '''
   support_bundle_binary_name = "deployment_support.py"
   src_support_bundle_binary_path = os.path.join('.',
                                                 support_bundle_binary_name)
   remote_support_bundle_binary_path = os.path.join(tempfile.gettempdir(),
                                                  support_bundle_binary_name)
 
   expected_docker_containers = BLOCKCHAIN_CONTAINERS[blockchain_type]
 
   log.info("")
   log.info("**** Collecting Support bundle ****")
   try:
      for replica in replicas:
         log.info("Concord IP: {}".format(replica))
         log.info(
            "  Upload support-bundle generation script onto concord node '{}'...".format(
               replica))
 
         if sftp_client(replica, CONCORD_USERNAME, CONCORD_PASSWORD,
                        src_support_bundle_binary_path,
                        remote_support_bundle_binary_path, action="upload"):
            log.debug("  Saved at '{}:{}'".format(replica,
                                                 remote_support_bundle_binary_path))
 
            cmd_execute_collect_support_bundle = "python3 {} --concordIP {} " \
                                                 "--dockerContainers {}".format(
               remote_support_bundle_binary_path, replica,
               ' '.join(expected_docker_containers))
 
            log.info("  Gathering deployment support logs...")
            ssh_output = ssh_connect(replica, CONCORD_USERNAME,
                                     CONCORD_PASSWORD,
                                     cmd_execute_collect_support_bundle)
            log.debug("Output from script '{}': {}".format(
                                             remote_support_bundle_binary_path,
                                             ssh_output))
            supput_bundle_created = False
            if ssh_output:
               for line in ssh_output.split('\n'):
                  if "Support bundle created successfully:" in line:
                     support_bundle_to_upload = line.split(':')[-1].strip()
                     log.info(
                        "  Support bundle created successfully on concord node {}:{}".format(
                           replica, support_bundle_to_upload))
                     supput_bundle_created = True
 
                     log.info("  Exporting support bundle...")
                     if not os.path.exists(test_log_dir):
                        os.makedirs(test_log_dir)
                     dest_support_bundle = os.path.join(test_log_dir,
                                                        os.path.split(
                                                           support_bundle_to_upload)[
                                                           1])
                     if sftp_client(replica, CONCORD_USERNAME,
                                    CONCORD_PASSWORD,
                                    support_bundle_to_upload,
                                    dest_support_bundle,
                                    action="download"):
                        log.info("  {}".format(dest_support_bundle))
                     else:
                        log.error(
                           "Failed to copy support bundle from concord '{}'".format(
                              replica))
                     break
 
            if not supput_bundle_created:
               log.error(
                  "Failed to create support bundle for concord {}".format(
                     replica))
         else:
            log.error(
               "Failed to copy support bundle generation script to concord '{}'".format(
                  replica))
         log.info("")
 
   except Exception as e:
      log.error(e)
 
 
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
 
 
def sftp_client(host, username, password, src, dest, action="download", log_mode=None):
   '''
   Helper method to execute a command on a host via SSH
   :param host: IP of remote host
   :param username: username for FTP connection
   :param password: password for username
   :param src: Source file to FTP
   :param dest: Destination file to FTP
   :param action: download/upload
   :param log_mode: Override to log connectivity issue as a warning
   :return: FTP Status (True/False)
   '''
   warnings.simplefilter("ignore", cryptography.utils.CryptographyDeprecationWarning)
   logging.getLogger("paramiko").setLevel(logging.WARNING)
 
   result = False
   sftp = None
   transport = None
   try:
      transport = paramiko.Transport((host, 22))
      transport.connect(None, username, password)
 
      sftp = paramiko.SFTPClient.from_transport(transport)
 
      if action.lower() == "download":
         sftp.get(src, dest)
         cmd_verify_ftp = ["ls", dest]
         if execute_ext_command(cmd_verify_ftp):
            log.debug("File downloaded from {} successfully: {}".format(host, dest))
            result = True
      else:
         sftp.put(src, dest)
         cmd_verify_ftp = "ls {}".format(dest)
         ssh_output = ssh_connect(host, username,password, cmd_verify_ftp)
         log.debug(ssh_output)
         if ssh_output:
            if ssh_output.rstrip() == dest:
               log.debug("File uploaded to {} successfully: {}".format(host, dest))
               result = True
   except paramiko.AuthenticationException as e:
      log.error("Authentication failed when connecting to {}".format(host))
   except Exception as e:
      if log_mode == "WARNING":
         log.warning("On host {}: {}".format(host, e))
      else:
         log.error("On host {}: {}".format(host, e))
 
   if sftp:
      sftp.close()
   if transport:
      transport.close()
 
   return result
 
def check_replica_health(replicas):
   for blockchain_type, replica_ips in replicas.items():
      log.info("Verifying health on {} ({})".format(replica_ips, blockchain_type))
      for replica_ip in replica_ips:
         log.info("{}...".format(replica_ip))
 
         count = 0
         max_timeout = 60  # seconds
         start_time = time.time()
         docker_images_found = False
         command_to_run = "docker ps --format '{{.Names}}'"
         log.debug(
            "Waiting for all docker containers to be up on '{}' within {} seconds".format(
               replica_ip, max_timeout))
         while not docker_images_found:
            count += 1
            log.debug(
               "Verifying docker containers (attempt: {})...".format(
                  count))
            ssh_output = ssh_connect(replica_ip,
                                            CONCORD_USERNAME,
                                            CONCORD_PASSWORD,
                                            command_to_run)
            log.debug("SSH output: {}".format(ssh_output))
            if ssh_output:
               for container_name in BLOCKCHAIN_CONTAINERS[blockchain_type]:
                  if container_name not in ssh_output:
                     docker_images_found = False
                     if (time.time() - start_time) > max_timeout:
                        log.info("SSH output:\n{}".format(ssh_output))
                        log.error(
                           "Container '{}' not up and running on node '{}'".format(
                              container_name, replica_ip))
                        return False
                     else:
                        log.warning(
                           "Container '{}' not up and running on node '{}'".format(
                              container_name, replica_ip))
                        time.sleep(10)
                        break
                  else:
                     docker_images_found = True
                     log.debug(
                        "Container {} found in node '{}'".format(
                           container_name, replica_ip))
            else:
               return False
         log.debug("Docker containers verified on {}".format(replica_ip))
   return True
 
 
if __name__ == '__main__':
   logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s %(levelname)s %(message)s',
                       datefmt='%Y-%m-%d %H:%M:%S')
   log = logging.getLogger(__name__)
 
   main(sys.argv)