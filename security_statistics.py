#!/usr/bin/env python

"""

.. module:: security_statistics
   :platform: Unix
   :synopsis: Analyze the Security Tracker commit history
.. moduleauthor:: Federico Ceratto <federico.ceratto@gmail.com>


# Git secure-testing repo configuration:
git config pack.windowMemory "100m"
git config pack.packSizeLimit "100m"
git config pack.threads "4"

"""

from bottle import template
from beaker.cache import CacheManager
from collections import Counter
from collections import defaultdict
from datetime import datetime
from optparse import OptionParser
from socket import gethostname
from time import time
import cairoplot
import json
import logging
import os
import re
import requests
import shutil
import subprocess


jpath = os.path.join

CACHE_DIR = '.cache'
CONTRIBUTORS_API_POST_URI = 'https://contributors.debian.org/contributors/post'
CONTRIBUTORS_API_TOKEN_FNAME = '.contributors_auth_token'
CVE_LIST_LOG_DIFF_FNAME = 'cve_list_log_diff'
GIT_REPO_LOCATION = './secure-testing'
LOG_FNAME = 'log'

log = None

cache = CacheManager(
    data_dir=jpath(CACHE_DIR, 'data'),
    enabled=True,
    expire=None,
    log_file=None,
    type='dbm',
    lock_dir=jpath(CACHE_DIR, 'lock'),
)

cache_db = cache.get_cache('mini_stats_db')


def timer(fn):
    def wrapper(*args, **kw):
        log.debug("Starting %s", fn.__name__)
        start_time = time()
        out = fn(*args, **kw)
        run_time = time() - start_time
        log.debug("%s ran in %f", fn.__name__, run_time)
        return out

    return wrapper


def setup_logging(debug):
    """Setup logging
    """
    global log
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            #format='(%(funcName)s) %(message)s',
            format='%(relativeCreated).0f %(levelname)s (%(funcName)s) %(message)s',
            datefmt = '%H:%M:%S' # %z for timezone
        )
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            filename=LOG_FNAME,
            format='%(asctime)s %(levelname)s (%(funcName)s) %(message)s',
            datefmt = '%Y-%m-%d %H:%M:%S' # %z for timezone
        )

    log = logging.getLogger()


def progress_gen(description, total_value):
    """Generator that prints progress updates.
    :yields: None
    """
    n = 0
    percentage = 0
    while True:
        n += 1
        new_percentage = int(100.0 * n / total_value)
        if new_percentage != percentage:
            log.info("[%s: %.2d%%]" % (description, new_percentage))
            percentage = new_percentage

        yield

progress_cve_additions = progress_gen('additions', 98422)
progress_cve_deletions = progress_gen('deletions', 32668)

class CVEHistoryParser(object):

    _version_package_re = re.compile(r"""

        (\[
            (?P<version>
                etch
                |jessie
                |lenny
                |sarge
                |sid
                |squeeze
                |wheezy
                |woody
            )
        \])?  # optional version, e.g. [etch] [wheezy]
        \ *-\                       # "<optional_whitespaces>-<whitespace>"
        (?P<pkg>[\.\+a-z0-9-]+)          # package name

        (                           # optional package version
            \ +                                       # at least one space
            (?P<pkg_epoch>[0-9]+:)?                         # optional epoch
            (?P<pkg_upstream_version>[A-Za-z0-9\.\+-:~]+)   # upstream version
            (-(?P<pkg_debian_version>[A-Za-z0-9\.\+-:~]+))? # debian version
        )?
        (\ +<unfixed>)?
        (\ +<itp>)?
        (\ +<removed>)?
        (\ +<not-affected>)?
        (
          \ +                               # at least one space
          \(
            (?P<par>[-\ a-z0-9;\#]+)
          \)
        )?
    """, re.VERBOSE)
    """
            (                               # many '; '-separated chunks
                (;\ +)?
                (bug\ \#(?P<bug_num>[0-9]+)) # a bug
                |(?P<lev>high|medium|low|unknown|unimportant)
                |(?P<bug_filed>bug filed)
            )+
"""

    def __init__(self, options):
        self._options = options
        self._contributors = {}
        self._cvesd = {}
        self._deleted_cves = {}
        self._deleted_xxxx_cves = {}

    @property
    def contributors(self):
        return self._contributors

    def process_cve_list_history(self):
        """Process commits to the CVE list file.
        """
        log.info("Processing CVE list commit history")
        commits = self.fetch_commits_list()
        #commits = commits[:900]  # FIXME: testing
        log.info("%d commits to be processed" % len(commits))
        assert len(commits) > 19

        cvesd = {} # (num, title) ->

        for cnt, commit_line in enumerate(commits):
            if cnt % 100 == 0:
                log.debug("%d%%" % (cnt * 100 / len(commits)))

            if not commit_line:
                continue

            commit_hash, author, tstamp = commit_line.split()
            date = datetime.fromtimestamp(int(tstamp))

            self.update_contributors_data(author, date)

            block = self.fetch_commit_diff(commit_hash)
            self.process_cve_list_diff_to_a_dict(commit_hash, date, block, cvesd)

        log.info("Last commit date: %s" % str(date))
        return cvesd


    def process_contributors_data(self, author_line, date):
        author = author_line.split()[1]
        try:
            self._contributors[author]['end'] = date
            self._contributors[author]['cnt'] += 1
        except KeyError:
            self._contributors[author] = {'begin': date, 'end': date, 'cnt': 1}

    def update_contributors_data(self, author, date):
        try:
            self._contributors[author]['end'] = date
            self._contributors[author]['cnt'] += 1
        except KeyError:
            self._contributors[author] = {'begin': date, 'end': date, 'cnt': 1}

    def merge_guest_contributors(self):
        for glogin in self._contributors.keys():
            if not glogin.endswith('-guest'):
                continue

            login = glogin[:-6]
            if login in self._contributors:
                m = self._contributors[login]
                g = self._contributors[glogin]
                log.info('merging %s %s %s' % (login, repr(g), repr(m)))
                assert g['start'] < m['start']
                assert g['end'] < m['end']
                m['start'] = g['start']
                m['end'] = g['end']
                m['cnt'] += g['cnt']

                del(self._contributors[glogin])


    def process_cve_list_diff_to_a_dict(self, commit_hash, date, commit_block, cvesd):

        cve_num = None
        title = None

        # For each CVE commit_block in a commit
        for cve_block in self.split_commit_in_cves(commit_block[1:]):
            if cve_block is None:
                continue

            header = cve_block[0]
            cve_num_title = header[1:].split(None, 1)

            cve_num = cve_num_title[0]
            title = cve_num_title[1].strip() if len(cve_num_title) > 1 else ''
            cve_num = cve_num.rstrip(':').rstrip(',')

            #assert 'CVE' in cve_num, repr(commit_block[:10])

            if cve_num == 'CVE-2005-XXXX' and title=='[XSS in Turba]':
                continue
            elif 'CVE-2005-XXXX' in header and title == '':
                continue

            if header.startswith('+'):
                # A new CVE is being added
                if (cve_num, title) not in cvesd:
                    if cve_num in self._deleted_cves:
                        target = self._deleted_cves.pop(cve_num)
                    elif title in self._deleted_xxxx_cves:
                        target = self._deleted_xxxx_cves.pop(title)


                    else:
                        target = {
                            'reserved': False,
                            'rejected': False,
                            'todo_check': False,
                            'packages': set(),
                            'bugs': set(),
                            'cnt': 1,
                            'dsas': set(),
                            'not-for-us': False,
                            'first_seen_date': None,
                            'last_modified_date': None,
                            'processed_date': None,
                        }
                        cvesd[(cve_num, title)] = target
                else:
                    #FIXME: log.info("duplicate CVE %s %s" % (cve_num, title))
                    target = cvesd[(cve_num, title)]
                    target['cnt'] += 1

            elif header.startswith('-'):
                # An existing CVE is being removed
                try:
                    target = cvesd[(cve_num, title)]
                    if target['cnt'] > 1:
                        #FIXME :log.info("deleting duplicate CVE %s %s" % (cve_num, title))
                        target['cnt'] -= 1
                    else:
                        if 'XXXX' in cve_num:
                            if title:
                                self._deleted_xxxx_cves[title] = target
                        else:
                            self._deleted_cves[cve_num] = target

                        del(target)

                except KeyError:
                    log.info("deleting missing CVE %s %s" % (cve_num, title))

                #
                #
                additions = set(l[1:].strip() for l in cve_block[1:]
                    if l.startswith('+'))
                #FIXME assert not additions, '\n'.join(cve_block)
                deletions = set(l[1:].strip() for l in cve_block[1:]
                    if l.startswith('-'))
                #
                #
                continue  # Skip the rest of the block

            else:
                target = cvesd[(cve_num, title)]
                # CVE already in cvesd
                assert (cve_num, title) in cvesd, repr(cve_block)

            # Extract lines that are being added or removed
            additions = set(l[1:].strip() for l in cve_block[1:]
                if l.startswith('+'))
            deletions = set(l[1:].strip() for l in cve_block[1:]
                if l.startswith('-'))

            # Remove uninteresting lines
            ignore_startswith = ('NOTE', 'HELP', 'begin claimed by ', 'begin claim by',
                    'end claimed by ', 'end claim by ', 'STOP: ')

            for l in additions.copy():
                if not l or l.startswith(ignore_startswith):
                    additions.discard(l)

            for l in deletions.copy():
                if not l or l.startswith(ignore_startswith):
                    deletions.discard(l)


            if additions or deletions:
                target['last_modified_date'] = date

            if cve_num == 'CVE-2008-4951':
                log.debug(cve_block)
                if additions or deletions:
                    log.debug('---')
                    log.debug(additions)
                    log.debug(deletions)
                    log.debug('---')

            for line in deletions:
                if line.startswith(('TODO:', 'TOOD:')):
                    target['processed_date'] = date
                    if line.startswith('TODO: check'):
                        target['todo_check'] = False


            for line in additions:
                if line.startswith(('NOT-FOR-US', 'NFU: ')):  # Not for us.
                    target['not-for-us'] = True

                elif line.startswith(('{DSA-', '{DTSA-')) and line[-1] == '}':
                    # DSA / DTSA related
                    dsas = line[1:-1].split()
                    dsas = [d for d in dsas if d.startswith('DSA')]
                    target['dsas'].update(dsas)

                elif line.startswith('{CVE-'):  # CVE related
                    pass

                elif line.startswith('TODO: check'):
                    target['todo_check'] = True

                elif line.startswith(('TODO:', 'TOOD:')):  # TODO
                    pass

                elif line.startswith('REJECTED'):
                    target['rejected'] = True

                elif line.startswith('RESERVED'):
                    target['reserved'] = True

                elif line.startswith('NO- '):  # Relation to a package
                    pass

                elif line.startswith('NO[') and '] - ' in line:  # Relation to a package
                    pass

                else:
                    match = re.match(self._version_package_re, line)
                    if match:
                        d = match.groupdict()
                        try:
                            target['packages'].add( (d['pkg'], date))
                        except:
                            log.error("Failed deletion %s" % repr(cve_block))


                        if d['par']:
                            #log.debug("par |%s| [%s]" % (d['par'], line))
                            for chunk in d['par'].split(';'):
                                chunk = chunk.strip()
                                if chunk.startswith('bug #'):
                                    bug_num = chunk[5:]
                                    target['bugs'].add(
                                        (int(bug_num), date)
                                    )

                                elif chunk in ('high', 'medium', 'low',
                                    'unimportant', 'unknown'):
                                    #cves[cve_num]['priority'] = chunk
                                    pass

                                elif chunk == 'bug filed':
                                    pass

                                else:
                                    # unknown format
                                    pass
                                    #FIXME
                                    #log.debug('uf>>' +line)


                    else:
                        pass
                        #FIXME: log.debug("Unknown line for %s: '%s'" % (cve_num, line))



            cvesd[(cve_num, title)] = target
            #log.info(date, new_cves, updated_cves)

        #log.info("Processed %d commits" % commit_cnt)
        #log.info("Last commit date: %s" % date)

    def process_cve_list_diff_to_memory(self, commit_block, cvesd):

        # one commit_block = one commit
        commit_label, commit_short_hash = commit_block[0].split()
        commit_short_hash = commit_short_hash[:8]
        assert commit_label == 'commit'
        assert commit_block[1].startswith('Author:')
        assert commit_block[2].startswith('Date:')
        cve_num = None

        # Date:   Thu Oct 20 11:18:17 2005 +0000
        date = commit_block[2].split(None, 1)[1]
        date = date.rsplit(None, 1)[0]
        date = datetime.strptime(date, '%a %b %d %X %Y')
        title = None
        self.process_contributors_data(commit_block[1], date)

        # For each CVE commit_block in a commit
        for cve_block in self.split_commit_in_cves(commit_block[1:]):
            if cve_block is None:
                continue

            header = cve_block[0]
            cve_num_title = header[1:].split(None, 1)

            cve_num = cve_num_title[0]
            title = cve_num_title[1].strip() if len(cve_num_title) > 1 else ''
            cve_num = cve_num.rstrip(':').rstrip(',')

            #assert 'CVE' in cve_num, repr(commit_block[:10])

            if cve_num == 'CVE-2005-XXXX' and title=='[XSS in Turba]':
                continue
            elif 'CVE-2005-XXXX' in header and title == '':
                continue

            if header.startswith('+'):
                # A new CVE is being added
                if (cve_num, title) not in cvesd:
                    if cve_num in self._deleted_cves:
                        target = self._deleted_cves.pop(cve_num)
                    elif title in self._deleted_xxxx_cves:
                        target = self._deleted_xxxx_cves.pop(title)


                    else:
                        target = {
                            'reserved': False,
                            'rejected': False,
                            'todo_check': False,
                            'packages': set(),
                            'bugs': set(),
                            'cnt': 1,
                            'dsas': set(),
                            'not-for-us': False,
                            'first_seen_date': None,
                            'last_modified_date': None,
                            'processed_date': None,
                        }
                        cvesd[(cve_num, title)] = target
                else:
                    #FIXME: log.info("duplicate CVE %s %s" % (cve_num, title))
                    target = cvesd[(cve_num, title)]
                    target['cnt'] += 1

            elif header.startswith('-'):
                # An existing CVE is being removed
                try:
                    target = cvesd[(cve_num, title)]
                    if target['cnt'] > 1:
                        #FIXME :log.info("deleting duplicate CVE %s %s" % (cve_num, title))
                        target['cnt'] -= 1
                    else:
                        if 'XXXX' in cve_num:
                            if title:
                                self._deleted_xxxx_cves[title] = target
                        else:
                            self._deleted_cves[cve_num] = target

                        del(target)

                except KeyError:
                    log.info("deleting missing CVE %s %s" % (cve_num, title))

                #
                #
                additions = set(l[1:].strip() for l in cve_block[1:]
                    if l.startswith('+'))
                #FIXME assert not additions, '\n'.join(cve_block)
                deletions = set(l[1:].strip() for l in cve_block[1:]
                    if l.startswith('-'))
                #
                #
                continue  # Skip the rest of the block

            else:
                target = cvesd[(cve_num, title)]
                # CVE already in cvesd
                assert (cve_num, title) in cvesd, repr(cve_block)

            # Extract lines that are being added or removed
            additions = set(l[1:].strip() for l in cve_block[1:]
                if l.startswith('+'))
            deletions = set(l[1:].strip() for l in cve_block[1:]
                if l.startswith('-'))

            # Remove uninteresting lines
            ignore_startswith = ('NOTE', 'HELP', 'begin claimed by ', 'begin claim by',
                    'end claimed by ', 'end claim by ', 'STOP: ')

            for l in additions.copy():
                if not l or l.startswith(ignore_startswith):
                    additions.discard(l)

            for l in deletions.copy():
                if not l or l.startswith(ignore_startswith):
                    deletions.discard(l)


            if additions or deletions:
                target['last_modified_date'] = date

            if cve_num == 'CVE-2008-4951':
                log.debug(cve_block)
                if additions or deletions:
                    log.debug('---')
                    log.debug(additions)
                    log.debug(deletions)
                    log.debug('---')

            for line in deletions:
                if line.startswith(('TODO:', 'TOOD:')):
                    target['processed_date'] = date
                    if line.startswith('TODO: check'):
                        target['todo_check'] = False


            for line in additions:
                if line.startswith(('NOT-FOR-US', 'NFU: ')):  # Not for us.
                    target['not-for-us'] = True

                elif line.startswith(('{DSA-', '{DTSA-')) and line[-1] == '}':
                    # DSA / DTSA related
                    dsas = line[1:-1].split()
                    dsas = [d for d in dsas if d.startswith('DSA')]
                    target['dsas'].update(dsas)

                elif line.startswith('{CVE-'):  # CVE related
                    pass

                elif line.startswith('TODO: check'):
                    target['todo_check'] = True

                elif line.startswith(('TODO:', 'TOOD:')):  # TODO
                    pass

                elif line.startswith('REJECTED'):
                    target['rejected'] = True

                elif line.startswith('RESERVED'):
                    target['reserved'] = True

                elif line.startswith('NO- '):  # Relation to a package
                    pass

                elif line.startswith('NO[') and '] - ' in line:  # Relation to a package
                    pass

                else:
                    match = re.match(self._version_package_re, line)
                    if match:
                        d = match.groupdict()
                        try:
                            target['packages'].add( (d['pkg'], date))
                        except:
                            log.error("Failed deletion %s" % repr(cve_block))


                        if d['par']:
                            #log.debug("par |%s| [%s]" % (d['par'], line))
                            for chunk in d['par'].split(';'):
                                chunk = chunk.strip()
                                if chunk.startswith('bug #'):
                                    bug_num = chunk[5:]
                                    target['bugs'].add(
                                        (int(bug_num), date)
                                    )

                                elif chunk in ('high', 'medium', 'low',
                                    'unimportant', 'unknown'):
                                    #cves[cve_num]['priority'] = chunk
                                    pass

                                elif chunk == 'bug filed':
                                    pass

                                else:
                                    # unknown format
                                    pass
                                    #FIXME
                                    #log.debug('uf>>' +line)


                    else:
                        pass
                        #FIXME: log.debug("Unknown line for %s: '%s'" % (cve_num, line))



            cvesd[(cve_num, title)] = target
            #log.info(date, new_cves, updated_cves)

        #log.info("Processed %d commits" % commit_cnt)
        #log.info("Last commit date: %s" % date)

    def split_commit_in_cves(self, commit_block):
        block = None
        for line in commit_block:
            if line.startswith((' CVE-', '+CVE-', '-CVE-')):
                # New CVE block
                yield block

                block = [line]
                continue

            # A regular line, nota a CVE "header"
            if line.startswith(('--- ', '+++ ', '@@ ', 'index ', 'diff --git ')):
                # Skip lines like:
                # diff --git a/data/CVE/list b/data/CVE/list
                # index 692d171..866aa94 100644
                # --- a/data/CVE/list
                # +++ b/data/CVE/list
                # @@ -1,3 +1,6 @@
                continue

            if block is not None:
                block.append(line)

        yield block


    def upload_contributors_data(self):
        """Upload contributors data to Debian Contributors
        """
        batch = []
        for login, user_data in self._contributors.iteritems():
            begin = user_data['begin'].strftime('%Y-%m-%d')
            end = user_data['end'].strftime('%Y-%m-%d')
            d = {
                'id': [
                    {
                        'type': 'login',
                        'id': login,
                    },
                ],
                'contributions': [
                    {
                        'type': 'security-tracker',
                        'begin': begin,
                        'end': end,
                    },
                ]
            }
            batch.append(d)

        fields = dict(
            source="Debian Security Tracker",
            auth_token="HIDDEN",
        )
        files = dict(
            data=json.dumps(batch),
        )

        with open(CONTRIBUTORS_API_TOKEN_FNAME) as f:
            auth_token = f.read().strip()

        fields['auth_token'] = auth_token.strip()

        r = requests.post(CONTRIBUTORS_API_POST_URI, data=fields, files=files)
        log.info(r.text)

    @timer
    def fetch_commits_list(self):
        """Fetch full list of commits from Git from the oldest to the newest
        """
        log.info("Fetching commits list")
        return self._run_git_command(
            'log --format="%H %cn %ct" --reverse data/CVE/list',
            silent=True,
        )

    @cache.cache('commit_diff')
    def fetch_commit_diff(self, commit_hash):
        """Fetch a commit diff, possibly from cache
        """
        return self._run_git_command("diff -U10 --no-color %s^..%s data/CVE/list" \
            % (commit_hash, commit_hash), silent=True)

    def _run_git_command(self, cmd, silent=False):
        """Run a git command in the repository
        """
        cmd = "git %s" % cmd
        cwd = os.getcwd()
        try:
            os.chdir(jpath(cwd, GIT_REPO_LOCATION))
            if not silent:
                log.info("Running %s" % cmd)
            out = subprocess.check_output(cmd, shell=True)
        finally:
            os.chdir(cwd)

        out = out.split('\n')
        if not silent:
            for l in out:
                log.debug(l)

        return out

def parse_cli_args():
    """Parse command line args, populate private attributes."""
    parser = OptionParser()
    parser.add_option('--udd-database', help='UDD database', default='udd')
    parser.add_option('--udd-host', help='UDD hostname', default='udd.debian.org')
    parser.add_option('--udd-port', help='UDD port', default=5452)
    parser.add_option('--udd-user', help='UDD user', default='guest')
    parser.add_option('--upload-contributors', action='store_true',
        help="""upload data to the Debian Contributors API
        (implies --update-repository)""")
    parser.add_option('-d', '--debug', help='debug mode', action='store_true',
        default=False)
    parser.add_option('--update-repository', action='store_true',
        help='Update local SVN/Git repository')
    parser.add_option('--generate-charts', action='store_true',
        help="Generate HTML charts")
    parser.add_option('--charts-dir', default='output',
        help="HTML charts output directory")

    options, args = parser.parse_args()
    if options.upload_contributors:
        options.update_repository = True

    return options, args


class StatsGenerator(object):
    def __init__(self, options):
        self._parse_cli_args(options)
        #self._dbconn = psycopg2.connect(
        #    host=self._udd_host,
        #    port=self._udd_port,
        #    user=self._udd_user,
        #    database=self._udd_database,
        #)
        self._bug_re = re.compile('\(bug #([0-9]+)')
        self._output_dir = options.charts_dir.rstrip('/')
        self._tmp_output_dir = self._output_dir + '.tmp'
        self._create_output_dir()

    def _create_output_dir(self):
        log.info("Output dir: %s Tmp dir: %s", self._output_dir, self._tmp_output_dir)
        os.mkdir(self._tmp_output_dir)

    def _parse_cli_args(self, options):
        """Parse command line args, populate private attributes."""
        self._udd_database = options.udd_database
        self._udd_host = options.udd_host
        self._udd_port = options.udd_port
        self._udd_user = options.udd_user#

    def update_cve_repository(self):
        """Update CVE Git repository and diff file
        """
        self._run_git_command("svn rebase")

    def _run_git_command(self, cmd, silent=False):
        """Run a git command in the repository
        """
        cmd = "git %s" % cmd
        cwd = os.getcwd()
        try:
            os.chdir(jpath(cwd, GIT_REPO_LOCATION))
            if not silent:
                log.info("Running %s" % cmd)
            out = subprocess.check_output(cmd, shell=True)
        finally:
            os.chdir(cwd)

        out = out.split('\n')
        if not silent:
            for l in out:
                log.debug(l)

        return out


    _version_package_re = re.compile(r"""

        (\[
            (?P<version>
                etch
                |jessie
                |lenny
                |sarge
                |sid
                |squeeze
                |wheezy
                |woody
            )
        \])?  # optional version, e.g. [etch] [wheezy]
        \ *-\                       # "<optional_whitespaces>-<whitespace>"
        (?P<pkg>[\.\+a-z0-9-]+)          # package name

        (                           # optional package version
            \ +                                       # at least one space
            (?P<pkg_epoch>[0-9]+:)?                         # optional epoch
            (?P<pkg_upstream_version>[A-Za-z0-9\.\+-:~]+)   # upstream version
            (-(?P<pkg_debian_version>[A-Za-z0-9\.\+-:~]+))? # debian version
        )?
        (\ +<unfixed>)?
        (\ +<itp>)?
        (\ +<removed>)?
        (\ +<not-affected>)?
        (
          \ +                               # at least one space
          \(
            (?P<par>[-\ a-z0-9;\#]+)
          \)
        )?
    """, re.VERBOSE)
    """
            (                               # many '; '-separated chunks
                (;\ +)?
                (bug\ \#(?P<bug_num>[0-9]+)) # a bug
                |(?P<lev>high|medium|low|unknown|unimportant)
                |(?P<bug_filed>bug filed)
            )+
"""

    def split_commit_in_cves(self, commit_block):
        block = None
        for line in commit_block:
            if line.startswith((' CVE-', '+CVE-', '-CVE-')):
                # New CVE block
                yield block

                block = [line]
                continue

            # A regular line, nota a CVE "header"
            if line.startswith(('--- ', '+++ ', '@@ ', 'index ', 'diff --git ')):
                # Skip lines like:
                # diff --git a/data/CVE/list b/data/CVE/list
                # index 692d171..866aa94 100644
                # --- a/data/CVE/list
                # +++ b/data/CVE/list
                # @@ -1,3 +1,6 @@
                continue

            if block is not None:
                block.append(line)

        yield block


    def process_cve_list_diff(self, commit_block):

        # one commit_block = one commit
        commit_label, commit_short_hash = commit_block[0].split()
        commit_short_hash = commit_short_hash[:8]
        assert commit_label == 'commit'
        assert commit_block[1].startswith('Author:')
        assert commit_block[2].startswith('Date:')
        cve_num = None

        # Date:   Thu Oct 20 11:18:17 2005 +0000
        date = commit_block[2].split(None, 1)[1]
        date = date.rsplit(None, 1)[0]
        date = datetime.strptime(date, '%a %b %d %X %Y')
        title = None

        # For each CVE commit_block in a commit
        for cve_block in self.split_commit_in_cves(commit_block):

            header = cve_block[0]
            if header[0] in (('+', '-')):
                cve_num_title = header[1:].split(None, 1)
            else:
                cve_num_title = header.split(None, 1)

            cve_num = cve_num_title[0]
            title = cve_num_title[1].strip() if len(cve_num_title) > 1 else ''
            cve_num = cve_num.rstrip(':').rstrip(',')

            banned_cves = ('CVE-2005-3299', 'CVE-2005-3300', 'CVE-2001-0683',
                'CVE-2005-0134')
            if cve_num in banned_cves:
                continue
            elif cve_num == 'CVE-2005-XXXX' and title=='[XSS in Turba]':
                continue
            elif 'CVE-2005-XXXX' in header and title == '':
                continue

            if header.startswith('+'):
                # A new CVE is being added
                count = self.execute_udd_query(
                    """SELECT count(*) FROM cves WHERE number = %s
                    AND title = %s;""",
                    (cve_num, title)
                ).fetchone()[0]
                if count == 0:
                    self.execute_udd_query("""INSERT INTO cves
                        (number, title) VALUES (%s, %s);""",
                        (cve_num, title)
                    )
                    progress_cve_additions.next()
                else:
                    log.info("skipping %s %s" % (cve_num, title))

            elif header.startswith('-'):
                # An existing CVE is being removed
                self.execute_udd_query("""DELETE FROM cves
                    WHERE number = %s
                    AND title = %s;""",
                    (cve_num, title)
                )
                progress_cve_deletions.next()
                continue

            for line in cve_block[1:]:
                line = line.rstrip()


                if not line.startswith('+'):
                    # No new "tags" are being added in this line, just continue
                    continue

                if 'begin claimed by' in line:
                    continue

                if not cve_num:
                    log.info('[NO CVE line %s]' % line)
                    for x in block[:20]:
                        log.info('>%s' % x)

                assert cve_num, block

                # A new line is being added to a CVE

                line = line[1:].lstrip()
                if not line:
                    pass

                elif line.startswith(('NOT-FOR-US', 'NFU: ')):  # Not for us.
                    #cves[cve_num]['not_for_us'] = True
                    pass

                elif line.startswith('{DSA-'):  # DSA related
                    pass

                elif line.startswith('{DTSA-'):  # DTSA related
                    pass

                elif line.startswith('{CVE-'):  # CVE related
                    pass

                elif line.startswith('NOTE'):  # A note
                    pass

                elif line.startswith('HELP: '):  # A note
                    pass

                elif line.startswith(('TODO:', 'TOOD:')):  # TODO
                    pass

                elif line.startswith('REJECTED'):
                    self.execute_udd_query(
                        """UPDATE cves
                            SET rejected = True
                            WHERE number = %s
                            AND title = %s;""",
                        (cve_num, title)
                    )

                elif line.startswith('RESERVED'):
                    self.execute_udd_query(
                        """UPDATE cves
                            SET reserved = True
                            WHERE number = %s
                            AND title = %s;""",
                        (cve_num, title)
                    )

                elif line.startswith('STOP: '):  # A note
                    pass

                elif line.startswith(('begin claimed by ', 'begin claim by',
                    'end claimed by ', 'end claim by ')):
                    pass

                elif line.startswith('NO- '):  # Relation to a package
                    pass

                elif line.startswith('NO[') and '] - ' in line:  # Relation to a package
                    pass

                else:
                    match = re.match(self._version_package_re, line)
                    if match:
                        d = match.groupdict()
                        try:
                            self.execute_udd_query(
                                """INSERT INTO cves_packages
                                (cve_id, package, creation_date)
                                VALUES (
                                    (
                                        SELECT id
                                        FROM cves
                                        WHERE cves.number = %s
                                        AND cves.title = %s
                                    ),
                                    %s,
                                    %s
                                );""",
                                (cve_num, title, d['pkg'], date)
                            )

                        except KeyError:
                            #cves[cve_num]['related_packages'] = [d['pkg'],]
                            pass

                        if d['par']:
                            #log.debug("par |%s| [%s]" % (d['par'], line))
                            for chunk in d['par'].split(';'):
                                chunk = chunk.strip()
                                if chunk.startswith('bug #'):
                                    bug_num = chunk[5:]
                                    q = self.execute_udd_query(
                                        """SELECT id
                                                FROM cves
                                                WHERE number = %s
                                                AND title = %s
                                        ;""",
                                        (cve_num, title)
                                    ).fetchone()
                                    if not q:
                                        log.info("missing cve %s '%s' in DB" % \
                                            (cve_num, title))
                                        #q = self.execute_udd_query(
                                        #    """SELECT * FROM cves WHERE number = %s ;""",
                                        #    (cve_num,)
                                        #).fetchone()
                                        #log.info(q)

                                    self.execute_udd_query(
                                        """INSERT INTO cves_bugs
                                        (cve_id, bug_id, creation_date)
                                        VALUES (
                                            (
                                                SELECT id
                                                FROM cves
                                                WHERE number = %s
                                                AND title = %s
                                            ),
                                            %s,
                                            %s
                                        );""",
                                        (cve_num, title, int(bug_num), date)
                                    )

                                elif chunk in ('high', 'medium', 'low',
                                    'unimportant', 'unknown'):
                                    #cves[cve_num]['priority'] = chunk
                                    pass

                                elif chunk == 'bug filed':
                                    pass

                                else:
                                    # unknown format
                                    log.debug('unknown format %s' % line)


                    else:
                        log.debug("%s: [%s]" % (cve_num, line))




            #log.info(date, new_cves, updated_cves)

        #log.info("Processed %d commits" % commit_cnt)
        #log.info("Last commit date: %s" % date)







    def populate_database_from_cve_history(self, cves):
        q_insert_cve = """INSERT INTO cves
            (affected_packages, affected_sources, arrival, last_modified,
            not_for_us, reserved, severity, status, title)
            VALUES (
                %(affected_packages)s, %(affected_sources)s, %(arrival)s,
                %(last_modified)s, %(not_for_us)s, %(reserved)s,
                %(severity)s, %(status)s, %(title)
            );"""

        for cve_num, cve in cves.iteritems():
            if 'not_for_us' in cve:
                continue
            try:
                s = q_insert_cve % cve
                log.debug(s)
            except:
                log.error(repr(cve))


    def generate_statistics_on_cve_processing(self, cves):
        log.debug("Generating stats")

        stat = {}
        skipped = 0 #FIXME
        for c in cves.itervalues():
            creation_date = c['processed_date'] or c['last_modified_date']

            if not creation_date:
                #log.error("Skipping %s" % repr(c))
                skipped += 1

                continue

            slot = (creation_date.year, creation_date.month)
            try:
                stat[slot]['opened'] += 1
            except KeyError:
                stat[slot] = {'opened': 1, 'updated': 0, 'update_deltas': []}

            try:
                ud = c['last_update_date']
                stat[slot]['updated'] += 1
                delta = ud - creation_date
                stat[slot]['update_deltas'].append(delta)
            except KeyError:
                # never had an update
                pass

        if skipped:
            log.error("%d skipped" % skipped)

        return stat

        for d in sorted(stat):
            # For each time slot
            deltas = stat[d]['update_deltas']
            within_a_day = within_a_week = 0
            for delta in deltas:
                seconds = delta.total_seconds()
                if seconds < 24 * 3600:
                    within_a_day += 1
                if seconds < 24 * 3600 * 7:
                    within_a_week += 1

            #p50 = sorted(deltas)[int(len(deltas) * .5)]
            #p90 = sorted(deltas)[int(len(deltas) * .9)]
            log.info("%s %s %s %s %s" % (d, stat[d]['opened'],
                stat[d]['updated'], within_a_day, within_a_week))


    def execute_udd_query(self, query, params=None):
        """Run a query against UDD, returns a cursor."""
        cursor = self._dbconn.cursor()
        if isinstance(query, tuple):
            cursor.execute(*query)
        else:
            try:
                cursor.execute(query, params)
            except Exception, e:
                log.error("%s %s" % (repr(query), repr(params)))
                raise

        self._dbconn.commit()
        return cursor

    def drop_udd_tables(self):
        log.info("Dropping UDD tables")
        self.execute_udd_query("""
        DROP TABLE IF EXISTS cves_packages;
        DROP TABLE IF EXISTS cves_bugs;
        DROP TABLE IF EXISTS cves;
        """)

    def create_udd_tables(self):
        log.info("Creating UDD tables")
        table_creation_query = """
            CREATE TABLE IF NOT EXISTS cves (
                id SERIAL PRIMARY KEY,
                arrival timestamp without time zone,
                affected_packages text,
                last_modified timestamp without time zone,
                not_for_us boolean,
                number text,            -- not unique in case of '-XXXX'
                reserved boolean,
                rejected boolean,
                severity text,
                status text,
                title text,
                affected_sources text,
                UNIQUE (number, title)
            );
            CREATE UNIQUE INDEX cves_mm_idx ON cves (number, title);

            --
            CREATE TABLE IF NOT EXISTS cves_packages (
                creation_date timestamp without time zone,
                cve_id integer REFERENCES cves ON DELETE CASCADE,
                package text NOT NULL,
                source text
            );
            --
            CREATE TABLE IF NOT EXISTS cves_bugs (
                bug_id integer NOT NULL,
                cve_id integer REFERENCES cves ON DELETE CASCADE,
                creation_date timestamp without time zone
            );
        """
        self.execute_udd_query(table_creation_query)





    def process_cve_list_from_repository(self):
        log.info("Processing CVEs from Git repository")
        cves = {}
        for block in read_cve_list_in_blocks():
            d = {}
            try:
                cve_id, title = block[0].split(None, 1)
            except ValueError:
                cve_id = block[0].split(None, 1)[0]
                title = None

            if 'XXXX' in cve_id:
                continue

            assert cve_id not in cves, cves[cve_id]
            d['title'] = title

            is_rejected = is_nfu = is_reserved = False
            bugs = []
            for line in block[1:]:
                if line == 'REJECTED':
                    is_rejected = True
                elif line == 'RESERVED':
                    is_reserved = True
                elif 'NOT-FOR-US: ' in line:
                    is_nfu = True
                elif line.startswith('- ') or line[0] == '[': # pkg line
                    bug_num = re.findall(bug_re, line)
                    if bug_num:
                        bugs.append(bug_num)

                elif line.startswith(('NOTE:', '{DSA-', '{DTSA-', 'TODO: ', '{CVE-')):
                    pass

                else:
                    log.info(repr(line))

            d['nfu'] = is_nfu
            d['rejected'] = is_rejected
            d['reserved'] = is_reserved
            d['bugs'] = bugs

            cves[cve_id] = d

        print 'Tot', sum(1 for d in cves.itervalues())
        print 'Rejected', sum(1 for d in cves.itervalues() if d['rejected'])
        print 'Reserved', sum(1 for d in cves.itervalues() if d['reserved'])
        print 'NFUs', sum(1 for d in cves.itervalues() if d['nfu'])
        print 'Bugs tot', sum(len(d['bugs']) for d in cves.itervalues())
        print 'Bugs', sum(1 for d in cves.itervalues() if d['bugs'])

    def count_sec_bugs_per_year(self):
        q = """
        select date_trunc('year', arrival), count(*) from bugs
        WHERE id IN (select id from bugs_tags where tag='security')
        and not (id in (select id from bugs_merged_with where id > merged_with))
        GROUP BY 1
        ORDER BY 1
        """
        cursor = self.execute_udd_query(q)
        return dict((date.year, num) for date, num in cursor)

    def count_bugs_per_month(self):
        q = """
        select date_trunc('month', arrival), count(*) from bugs
        WHERE id IN (select id from bugs_tags where tag='security')
        and not (id in (select id from bugs_merged_with where id > merged_with))
        GROUP BY 1
        ORDER BY 1
        """
        cursor = self.execute_udd_query(q)
        d = dict(("%d-%d" % (date.year, date.month), num) for date, num in cursor)
        return d

    def count_archived_bugs_per_year(self):
        q = """
        select date_trunc('year', arrival), count(*) from archived_bugs
        WHERE id IN (select id from archived_bugs_tags where tag='security')
        and not (id in (select id from bugs_merged_with where id > merged_with))
        GROUP BY 1
        ORDER BY 1
        """
        cursor = self.execute_udd_query(q)
        return dict((date.year, num) for date, num in cursor)

    def count_archived_bugs_per_month(self):
        q = """
        select date_trunc('month', arrival), count(*) from archived_bugs
        WHERE id IN (select id from archived_bugs_tags where tag='security')
        and not (id in (select id from bugs_merged_with where id > merged_with))
        GROUP BY 1
        ORDER BY 1
        """
        cursor = self.execute_udd_query(q)
        d = dict(("%d-%d" % (date.year, date.month), num) for date, num in cursor)
        return d

    def count_archived_bugs_per_year_from_cves(self, cves):
        return

    def count_archived_bugs_per_month_from_cves(self, cves):
        return

    def count_cves_per_years(self):
        stats = defaultdict(int)
        filename = './secure-testing/data/CVE/list' #FIXME
        with open(filename) as f:
            for line in f:
                if line.startswith('CVE-'):
                    year = line[4:8]
                    year = int(year)
                    stats[year] += 1

        return stats

    def unused(self):
        # Archived bugs, by opening year
        cursor.execute("""
        select date_trunc('year', arrival), count(*) from archived_bugs
        WHERE id IN (select id from archived_bugs_tags where tag='security')
        and not (id in (select id from bugs_merged_with where id > merged_with))
        GROUP BY 1
        ORDER BY 1
        LIMIT 20
        """)

    def _generate_chart(self, monthly_data, fname, height=200, width=800):
        """Generate SVG chart"""
        # monthly_data is expected to be:
        # {<metricname>: {<year>_<month>: <value>, ...}, ... }
        # e.g. {'foo': {'2011-01': 3}}

        assert isinstance(monthly_data, dict)

        all_years_months = set()
        for y_months in monthly_data.itervalues():
            for y_m in y_months:
                #assert len(y_m) == 7
                #assert y_m[4] == '-', repr(y_m)
                pass

            # Merge the timelines from every metric
            all_years_months.update(y_months)

        all_years_months = sorted(all_years_months)

        x_labels = [m if m.endswith('-01') else ''
            for m in all_years_months]

        metrics = {}
        for metricname, y_months_d in monthly_data.iteritems():
            values = []
            for y_m in all_years_months:
                v = y_months_d.get(y_m, 0)  # Pick 0 if a value is missing
                values.append(v)

            metrics[metricname] = values

        fname = jpath(self._tmp_output_dir, fname)
        log.info("Generating %s " % fname)

        cairoplot.dot_line_plot(
            fname,
            metrics,
            width,
            height,
            x_labels = x_labels,
            axis = True,
            grid = True,
            dots = True,
            series_legend = True,
            series_colors = ['blue', 'red', 'green', 'black'],
        )


    def generate_cve_chart(self, cves_per_year):

        data = {'CVEs per year': cves_per_year}
        self._generate_chart(data, 'cves')

    def generate_opened_bugs_chart(self, bugs_per_period, archived_bugs_per_period):

        # Sum the values from the two dictionaries
        tot_bugs = {
            t: bugs_per_period.get(t, 0) + archived_bugs_per_period.get(t, 0)
                for t in set(bugs_per_period).union(archived_bugs_per_period)
        }

        data = {
            'archived bugs per month': archived_bugs_per_period,
            'bugs per month': bugs_per_period,
            'total bugs per month': tot_bugs,
        }
        self._generate_chart(data, 'opened')


    def generate_cve_processing_chart(self, stat):
        log.debug("Generate CVE processing chart")

        opened = {}
        updated = {}
        within_a_day_history = {}
        within_a_week_history = {}
        for d in sorted(stat)[1:-1]:
            log.debug(d)
            month = "%d_%d" % d
            # For each time slot
            #deltas = stat[d]['update_deltas']
            #within_a_day = within_a_week = 0
            #for delta in deltas:
            #    seconds = delta.total_seconds()
            #    if seconds < 24 * 3600:
            #        within_a_day += 1
            #    if seconds < 24 * 3600 * 7:
            #        within_a_week += 1

            opened[month] = stat[d]['opened']
            updated[month] = stat[d]['updated']
            #within_a_day_history[month] = within_a_day
            #within_a_week_history[month] = within_a_week

        data = {
            'opened': opened,
            #'updated': updated,
            #'processed in 1d': within_a_day_history,
            #'processed in 1w': within_a_week_history,
        }
        self._generate_chart(data, 'cves_processing')



    def _get_cve_repo_git_commit_dates(self):
        """Get commits time distribution"""
        cmd = """log --pretty=format:%ci"""
        out = self._run_git_command(cmd, silent=True)
        # Line example: 2013-12-27 19:39:55 +0000
        out = map(str.strip, out)
        return out

    def generate_git_commits_chart(self):
        """Generate simple chart on commits time distribution"""

        out = self._get_cve_repo_git_commit_dates()
        commits_dates = [l[:7] for l in out if l]
        commits_per_month = Counter(commits_dates)

        data = {'commits per month': commits_per_month}
        self._generate_chart(data, 'git_commits')

    def generate_html_index(self, start_time):
        """Generate HTML index page"""
        log.info("Generating HTML index")

        generation_time = "%.0fs" % (time() - start_time)
        current_tstamp = datetime.now().isoformat().split('.')[0]

        html_page = template('index', dict(
            generation_time=generation_time,
            current_tstamp=current_tstamp,
            hostname=gethostname(),
        ))
        self.writefile(self._tmp_output_dir, 'index.html', html_page)


    def writefile(self, path, fname, content):
        """Write a file to disk"""
        fname = jpath(path, fname)
        with open(fname, 'w') as f:
            f.write(content)

        log.info("%s written" % fname)


    def generate_charts_from_db(self):
        start_time = time()
        cves_per_year = self.count_cves_per_years()
        bugs_per_year = self.count_sec_bugs_per_year()
        bugs_per_month = self.count_bugs_per_month()
        archived_bugs_per_year = self.count_archived_bugs_per_year()
        archived_bugs_per_month = self.count_archived_bugs_per_month()

        self.generate_cve_chart(cves_per_year)
        self.generate_opened_bugs_chart(bugs_per_month, archived_bugs_per_month)
        self.generate_html_index(start_time)

    def generate_charts_from_cves_dict(self, start_time, cves):
        #cves_per_year = self.count_cves_per_years()
        #bugs_per_year = self.count_sec_bugs_per_year()
        #archived_bugs_per_year = self.count_archived_bugs_per_year()
        #archived_bugs_per_month = self.count_archived_bugs_per_month()

        #self.generate_opened_bugs_chart(bugs_per_month, archived_bugs_per_month)
        #self.generate_html_index(start_time)
        stat = self.generate_statistics_on_cve_processing(cves)
        self.generate_cve_processing_chart(stat)

        archived_bugs_per_year = self.count_archived_bugs_per_year_from_cves(cves)

        bugs_per_month = Counter((c['processed_date'].strftime('%Y-%m')
            for c in cves.itervalues() if c['processed_date']))

        archived_bugs_per_month = Counter((c['processed_date'].strftime('%Y-%m')
            for c in cves.itervalues() if c['processed_date']))

        self.generate_opened_bugs_chart(bugs_per_month, archived_bugs_per_month)

        cves_per_year = Counter((c['processed_date'].strftime('%Y')
            for c in cves.itervalues() if c['processed_date']))
        self.generate_cve_chart(cves_per_year)

        self.generate_html_index(start_time)
        self.generate_license_page()
        self.copy_static_files()
        self.flip_tmp_output_dir()

    def generate_license_page(self):
        """Generate license page"""
        html_page = template('license')
        self.writefile(self._tmp_output_dir, 'license.html', html_page)

    def copy_static_files(self):
        """Copy the static directory"""
        dst = os.path.join(self._tmp_output_dir, 'static')
        shutil.copytree('static', dst)

    def flip_tmp_output_dir(self):
        """Flip output directory"""
        log.info("Renaming dir")
        shutil.rmtree(self._output_dir)
        os.rename(self._tmp_output_dir, self._output_dir)


def generate_short_summary(cves, contributors):
    """Generate short summary, update cache db
    """
    global cache_db
    summary = dict(
        todo_cnt = sum((1 for c in cves.itervalues() if c['todo_check'])),
        nfu_cnt = sum((1 for c in cves.itervalues() if c['not-for-us'])),
        reserved_cnt = sum((1 for c in cves.itervalues() if c['reserved'])),
        rejected_cnt = sum((1 for c in cves.itervalues() if c['rejected'])),
        nfu_pkgs_cnt = sum((1 for c in cves.itervalues() if not c['not-for-us']
            and not c['packages'])),
        contributors_cnt = len(contributors),
    )

    for k in sorted(summary):

        v = summary[k]
        try:
            delta = v - cache_db[k]
        except KeyError:
            delta = v

        ck = k.capitalize()
        log.info("%-18s: %8d Increase: %8d" % (ck, v, delta))

        #if k in ('nfu_cnt', 'reserved_cnt', 'rejected_cnt', 'contributors_cnt'):
        #    assert delta >= 0, "Negative delta - probably a bug"

        if delta:
            cache_db[k] = v



def main():
    options, args = parse_cli_args()
    setup_logging(options.debug)

    start_time = time()
    sg = StatsGenerator(options)
    hp = CVEHistoryParser(options)

    if options.update_repository:
        sg.update_cve_repository()

    if options.generate_charts:
        sg.update_cve_repository()
        sg.generate_git_commits_chart()

    cves = hp.process_cve_list_history()
    #hp.merge_guest_contributors()

    if options.upload_contributors:
        hp.upload_contributors_data()

    if options.generate_charts:
        sg.generate_charts_from_cves_dict(start_time, cves)

    generate_short_summary(cves, hp.contributors)

    #sg.populate_database_from_cve_history(cves)

    #sg.generate_charts_from_db()


if __name__ == '__main__':
    main()

