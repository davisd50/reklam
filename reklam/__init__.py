import argparse
import json
import re
import subprocess
import sys
from sparc.cli.command import CommandLaunch
from sparc.config.yaml.documents import SparcYamlConfigContainers

import logging
logger = logging.getLogger(__name__)

def getScriptArgumentParser(args=sys.argv):
    """Return ArgumentParser object
    
    Returns:
        ArgumentParser object that can be used to validate and execute the
        current script invocation.
    """
    # Description
    parser = argparse.ArgumentParser(
            description="A tool to reclaim disk space from iSCSI booted ZFS volumes.")

    # config_file
    parser.add_argument('config_file',
            help="path to config file")

    # concurrency
    parser.add_argument('-c',
            help="Number of concurrent jobs to run, defaults to 1",
            default=1,
            type=int)
    
    # --dry
    parser.add_argument('--dry', 
            help="Report change actions to STDOUT without actually performing them.",
            action="store_true")
    
    # --pdb
    parser.add_argument('--pdb', 
            help="drop to Python debugger for uncaught exceptions",
            action="store_true")
    
    # --verbose
    parser.add_argument('--verbose',
            action='store_true',
            help="Echo verbose messages to stdout.")
    
    # --debug
    parser.add_argument('--debug',
            action='store_true',
            help="Echo debug messages to stdout.")
    
    return parser


class Reklam(object):
    
    config = None #init's to a sparc.config.IConfigContainer provider
    
    def __init__(self, config_file):
        self.config = SparcYamlConfigContainers().first(config_file)
    
    def _salt_ssh_check_output_lines(self, roster_entry, cmd_string):
        c = CommandLaunch('salt-ssh', [roster_entry, '--out=json', '-r', cmd_string])
        logger.debug('launching sub-process with command arguments: {}'.format(list(c)))
        return json.loads( subprocess.check_output(c) )[roster_entry]['stdout'].split("\n")#raises on non-zero exits
    
    def get_itadm_list_target(self, roster_entry):
        lines = self._salt_ssh_check_output_lines(roster_entry, 'itadm list-target')
        #import pdb;pdb.set_trace()
        statuses = []
        for l in lines:
            entries = l.split()
            if len(entries) == 3:
                target = entries[0]
                state = entries[1]
                sessions = int(entries[2])
                status = (target, state, sessions,)
                logger.debug("discovered iscsi target status: {}".format(status))
                statuses.append(status)
        return statuses
    
    def get_stmfadm_list_tg(self, roster_entry):
        """return dict of entries, entry is {'tg-name': ['iqn1', 'iqn2'...]}
        """
        tgs = {}
        for l in [l.strip() for l in self._salt_ssh_check_output_lines(roster_entry, 'stmfadm list-tg -v') if l.strip()]:
            if 'Target Group:' in l:
                tg = l.split(": ")[1].strip()
                tgs[tg] = []
            else:
                tgs[tg].append(l.split(": ")[1].strip())
        logger.debug("discovered target groups: {}".format(tgs))
        return tgs
    
    def get_stmf_list_lu(self, roster_entry):
        lus = {}
        for l in [l.strip() for l in self._salt_ssh_check_output_lines(roster_entry, 'stmfadm list-lu -v') if l.strip()]:
            if 'LU Name:' in l:
                lu = l.split(": ")[1].strip()
                lus[lu] = {}
            else:
                _s = l.split(": ")
                lus[lu][_s[0].strip()] = _s[1].strip()
        logger.debug("discovered luns: {}".format(lus))
        return lus
    
    def get_stmf_view(self, roster_entry, lu):
        view = {}
        try:
            for l in [l.strip() for l in self._salt_ssh_check_output_lines(roster_entry, 'stmfadm list-view -l {}'.format(lu)) if l.strip()]:
                if 'View Entry: ' in l:
                    entry = l.split(": ")[1].strip()
                    view[entry] = {}
                else:
                    _s = l.split(": ")
                    view[entry][_s[0].strip()] = _s[1].strip()
            logger.debug("discovered lun {} view: {}".format(lu, view))
        except subprocess.CalledProcessError as e:
            if not 'no views found' in e.output:
                raise
        return view
    
    def get_stmf_views(self, roster_entry):
        views = {}
        for l in [l.strip() for l in self._salt_ssh_check_output_lines(roster_entry, 'stmfadm list-lu') if l.strip()]:
            if 'LU Name: ' in l:
                lu = l.split(": ")[1].strip()
                logger.debug("discovered lun {}".format(lu))
                views[lu] = self.get_stmf_view(roster_entry, lu)
        return views
    
    def get_matched_filesystems(self, config_entry):
        filesystems = []
            
        patterns = []
        for pattern in config_entry['filesystems']:
            patterns.append((pattern, re.compile(pattern), ))
        
            
        roster_entry = config_entry['salt_roster_host']
        lines = self._salt_ssh_check_output_lines(roster_entry, 'zfs list -H -o name')
        
        for filesystem in lines:
            logger.debug("discovered {} zfs filesystem on roster host {}".format(filesystem, roster_entry))
            for pattern, p in patterns:
                if not p.match(filesystem):
                    continue
                logger.debug("ZFS filesystem {} matched pattern {}".format(filesystem, pattern))
                filesystems.append(filesystem)
        return filesystems
    
    def go(self):
        """
         - filter targets with open sessions
         - trace target to tg
         - trace tg to a view
         - trace view to lu
         - trace lu to zfs file systems
        """
        
        for entry in self.config.sequence('Reklam'):
            logger.debug("Found Reklam config entry with value {}".format(entry))
            
            used_ips = set() #safety for config errors
            tg_map = {}
            for pattern in entry['TargetGroupIpMap'] :
                tg_map[re.compile(pattern)] = entry['TargetGroupIpMap'][pattern]
        
            #for f in self.get_matched_filesystems(entry):
            #    pass
            filesystems = self.get_matched_filesystems(entry)
            targets = self.get_itadm_list_target(entry['salt_roster_host'])
            tgs = self.get_stmfadm_list_tg(entry['salt_roster_host'])
            views = self.get_stmf_views(entry['salt_roster_host'])
            lus = self.get_stmf_list_lu(entry['salt_roster_host'])
            for target, state, sessions in targets:
                if not sessions:
                    logger.debug("skipping iSCSI target {} because there are no current sessions".format(target))
                    continue
                
                
                for tg in tgs:
                    if not target in tgs[tg]:
                        continue
                    
                    for lu in views:
                        for view in views[lu]:
                            if views[lu][view]['Target group'] != tg:
                                continue
                            
                            df = lus[lu]['Data File']
                            filesystem = df.split('/dev/zvol/rdsk/')[1].strip() #this is the impacted zfs file system
                            if not filesystem in filesystems:
                                continue
                            ip = None
                            for p in tg_map:
                                if p.match(tg):
                                    if ip:
                                        raise EnvironmentError("Illegally matched on multiple entries in the config target group mapping for tg {}".format(tg))
                                    else:
                                        ip = tg_map[p]
                                        if ip in used_ips:
                                            raise EnvironmentError("Illegally matched an IP address twice from config target group mapping for {}".format(ip))
                                        used_ips.add(ip)
                            if not ip:
                                logger.warning("Skipping valid target {} for target group {} with view for lun {} related to qualified zfs filesystem {} due to missing entry in config target group ip address map".format(target, tg, lu, filesystem))
                                continue
                            
                            logger.info("Found target {} for target group {} with view for lun {} related to qualified zfs filesystem {} for client IP address {}".format(target, tg, lu, filesystem, ip))
            
                    
                
                

def setup_logging(args):
    logger = logging.getLogger() # root logger
    
    if logger.level == logging.NOTSET:
        logger.setLevel(logging.WARN)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)d %(message)s'))
    
    logger.addHandler(handler)
    
    if args.verbose:
        logger.setLevel('INFO')
        logger.info("Info level logging enabled")
    if args.debug:
        logger.setLevel('DEBUG')
        logger.info("Debug level logging enabled")

def main():
    args = getScriptArgumentParser().parse_args()
    setup_logging(args)
    reklam = Reklam(args.config_file)
    try:
        reklam.go()
    except Exception:
        if args.pdb:
            import traceback, pdb
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            pdb.post_mortem(tb)
        else:
            raise

if __name__ == '__main__':
    main()