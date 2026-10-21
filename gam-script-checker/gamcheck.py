#!/usr/bin/env python3
"""
GAM Script Checker (gamcheck)
=============================================================================
Copyright (c) 2026 Paul Ogier, Outsource House (South Africa)
Website: https://osh.co.za | Email: support@osh.co.za
Training provided by Taming.Tech (https://taming.tech)

Google Workspace GAM7 Course on Udemy   https://taming.tech/GAMCourse
Google Workspace Admin Course on Udemy  https://www.taming.tech/GoogleWorkspaceAdmin
Google Workspace End-User Course on Udemy  https://www.taming.tech/TheCompleteWorkspaceCourse

Licence: Apache License 2.0 (full text in LICENSE at the repository root)

In plain English:
  - Free to use, including for commercial purposes.
  - Modify and redistribute freely; closed-source derivatives are allowed.
  - PLEASE KEEP THE ATTRIBUTION above intact. If you redistribute this
    file (modified or not), the copyright, contact, and course-link block
    at the top must stay in place. This is the one real obligation the
    licence puts on you (Apache 2.0 clause 4(c)) and it is what lets
    users find the original author and the training resources. Removing
    or replacing it is a licence violation.
  - No warranty: the disclaimer below is part of the licence terms.
  - "OSH", "Outsource House", and "Taming.Tech" are trademarks and are
    not licensed for use in your own product or marketing names
    (Apache 2.0 clause 6).

DISCLAIMER & LIMITATION OF LIABILITY:
This software is provided "AS IS", without warranty of any kind, express or
implied. The authors (Paul Ogier, Outsource House) and training providers
(Taming.Tech) accept NO RESPONSIBILITY for any damages, data loss, or system
issues that may arise from its use. A READ-ONLY verdict is a reading of the
script text, not a guarantee that running it is safe.

YOU ASSUME ALL RISK ASSOCIATED WITH THE USE OF THIS SOFTWARE.
=============================================================================

Author:       Paul Ogier
Created:      2026-09-13
Updated:      2026-10-21
Version:      0.4.4
Status:       Pre-release
Python:       3.9+
Dependencies: None. Stdlib only; never runs gam or the script it checks.

Reads a GAM script and reports what it would do, without running it.

Checks shell (.sh), PowerShell (.ps1), Windows batch (.bat/.cmd), Python (.py)
and GAM batch files (.txt) for gam commands, classifies each one against the
verb tables GAM7 itself parses (verbs/*.json, built by build_verb_table.py),
and scans the rest of the script for commands that damage the local machine.

Usage:
    python3 gamcheck.py SCRIPT [SCRIPT ...] [--json] [--quiet]
    python3 gamcheck.py              asks you to paste commands (so does --paste)
    some-command | python3 gamcheck.py -

Exit code is the worst verdict found:
    0 READ-ONLY, 1 CHANGES, 2 CANNOT TELL, 3 DESTRUCTIVE, 4 SUSPICIOUS

The checker never runs the script or gam. It reads text, so anything decided
at runtime is reported as CANNOT TELL rather than guessed.
"""
import argparse
import ast
import csv
import json
import re
import shlex
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

__version__ = '0.4.4'

HERE = Path(__file__).resolve().parent
VERBS_DIR = HERE / 'verbs'

READ, CHANGES, UNKNOWN, DESTRUCTIVE, SUSPICIOUS = range(5)
LEVEL_NAMES = ['READ-ONLY', 'CHANGES', 'CANNOT TELL', 'DESTRUCTIVE', 'SUSPICIOUS']

# Danger level per verb word, after GAM's own alias resolution. Older-version
# spellings (deprov, sig, pop3, ...) are listed too so legacy scripts classify.
# test_gamcheck.py fails if any verb in the three tables is missing here, so a
# new GAM verb cannot fall through to a default.
VERB_LEVEL = {}
for _level, _words in {
    READ: 'print show info list report whatis version help checkconn checkconnection check getcommand csvtest '
          'waitformailbox printacl showacl printevents infoevent comment get download export verify',
    CHANGES: 'add create update modify move copy import insert suspend unsuspend undelete untrash transfer claim '
             'collect hide unhide send sendemail sendreply watch signout accept append archive approve cancel '
             'cancelwipe close reopen draft draftemail importemail insertemail enable disable end process spam '
             'setup use upload rotate replace replacedomain label filter forward imap imap4 pop pop3 language '
             'profile signature sig vacation sendas delegate delegates addevent updateevent moveevent refresh '
             'request turnoff2sv issuecommand',
    DESTRUCTIVE: 'delete del remove clear purge wipe empty trash obliterate deprovision deprov dedup revoke block '
                 'sync yubikey deleteevent',
}.items():
    for _w in _words.split():
        VERB_LEVEL[_w] = _level

# Where the same word means something else in one scope.
SCOPE_LEVEL = {
    ('oauth', 'info'): READ,
    ('oauth', 'create'): CHANGES,
    ('oauth', 'update'): CHANGES,
    ('oauth', 'refresh'): CHANGES,
    ('oauth', 'export'): READ,
    ('oauth', 'delete'): DESTRUCTIVE,
}

WRAPPERS = {'batch', 'tbatch', 'csv', 'loop'}

# Words after which the next token is a value (a file name, a query, an address),
# never an option. A word that makes a command SAFER (doit missing, preview,
# addonly, untrash) only counts when it is not in a value position, so a file
# called "preview" or a query of "doit" cannot talk the verdict down.
VALUE_KEYWORDS = {'file', 'csvfile', 'gsheet', 'gdoc', 'gcsdoc', 'datafile', 'csvkmd', 'csvdata', 'query', 'queries',
                  'fullquery', 'matchfield', 'skipfield', 'keyfield', 'subkeyfield', 'datafield', 'select', 'name',
                  'description', 'email', 'id', 'ids', 'eventid', 'user', 'users', 'group', 'ou', 'orgunit', 'title',
                  'subject', 'label', 'labels', 'drivefilename', 'newfilename', 'additionalmembers', 'delivery',
                  'localfile', 'parentid', 'teamdriveid', 'shareddriveid', 'command', 'emailmatchpattern',
                  'emailclearpattern', 'emailretainpattern', 'product', 'productid', 'sku', 'skus'}

# gam all <subtype>: GAM's suffixes, spelled out
ALL_SUBTYPES = {'users_ns': 'non-suspended users', 'users_susp': 'suspended users',
                'users_ns_susp': 'users (suspended and not)', 'users_arch': 'archived users',
                'users_ns_arch': 'non-suspended and archived users', 'users_susp_arch': 'suspended and archived users'}

GMAIL_ITEMS = {'message': 'message', 'messages': 'message', 'thread': 'thread', 'threads': 'thread'}
TRUE_VALUES = {'on', 'true', 'yes', 'enable', 'enabled', '1'}
FALSE_VALUES = {'off', 'false', 'no', 'disable', 'disabled', '0'}

NOTES = {
    'suspend': 'blocks sign-in straight away; undone with unsuspend',
}

# Commands GAM refuses to carry out without the word doit: it counts what
# matches, prints "use doit" and stops. Read from GAM7 7.48.07 source
# (_processMessagesThreads, archiveMessages, forwardMessagesThreads,
# deleteFileRevisions, updateFileRevisions, _getCalendarDeleteEventOptions,
# getUpdateDeleteCIDeviceOptions, _getUpdateDeleteMobileOptions,
# updateCalendarAttendees). Gmail commands given explicit ids skip the check, and so
# does a mobile or Cloud Identity device named directly (getMobileDeviceEntity,
# getCIDeviceEntity and getCIDeviceUserEntity return doit=True): only a query is gated.
# purge event is NOT gated: _purgeCalendarEvents skips the gated delete, then moves
# the matched events into a temporary calendar and deletes it, without doit
# (dev tenant, GAM 7.48.01 and 7.48.20, 2026-10-06: a live event was destroyed;
# reported as GAM-team/GAM#1997, re-test when it closes).
DOIT_GATED = (
    {('user', v, o) for v in ('delete', 'modify', 'spam', 'trash', 'untrash', 'forward')
     for o in ('message', 'thread')}
    | {('user', 'archive', 'message')}
    | {('user', 'delete', 'filerevision'), ('user', 'update', 'filerevision'), ('user', 'delete', 'event'),
       ('user', 'update', 'calattendees'), ('calendar', 'deleteevent', None),
       ('calendar', 'delete', 'event'), ('main', 'delete', 'mobile'),
       ('main', 'update', 'mobile')}
    | {('main', v, o) for v in ('delete', 'update', 'cancelwipe', 'wipe') for o in ('device', 'deviceuser')}
    | {('main', 'approve', 'deviceuser'), ('main', 'block', 'deviceuser')}
)
# Of those, the ones whose max_to_<action> defaults to 1: with doit, GAM still
# skips any user where more than one item matches unless max_to_... is given.
MAX_TO_ONE = {k for k in DOIT_GATED if k[2] in ('message', 'thread', 'filerevision') and k[1] != 'archive'}

# Commands that accept preview, which lists the actions and changes nothing.
PREVIEW_ABLE = {('main', 'update', 'group'), ('main', 'update', 'cigroup'), ('user', 'create', 'license'),
                ('user', 'add', 'license'), ('user', 'delete', 'license'), ('user', 'sync', 'license'),
                ('user', 'transfer', 'drive'), ('user', 'transfer', 'ownership'), ('user', 'claim', 'ownership'),
                ('user', 'collect', 'orphans'), ('main', 'sync', 'device'), ('user', 'sync', 'chatmember')}

# gam update group|cigroups <group> <action>: the membership actions (doUpdateGroups).
GROUP_MEMBER_ACTIONS = {
    'add': (CHANGES, 'adds members to'), 'create': (CHANGES, 'adds members to'),
    'update': (CHANGES, 'changes member roles or delivery in'),
    'delete': (DESTRUCTIVE, 'removes members from'), 'remove': (DESTRUCTIVE, 'removes members from'),
    'sync': (DESTRUCTIVE, 'syncs the members of'), 'clear': (DESTRUCTIVE, 'removes all members from'),
}

# User commands where "delete" takes the user out of something rather than
# deleting the thing itself. {e} is the user entity. A level here overrides the verb's.
USER_RELATION = {
    ('delete', 'group'): (None, 'removes {e} from groups'),
    ('sync', 'group'): (None, 'syncs the group memberships of {e} (adds and removes)'),
    ('delete', 'license'): (None, 'removes licences from {e}'),
    ('sync', 'license'): (None, 'syncs the licences of {e} (adds and removes)'),
    ('delete', 'calendar'): (CHANGES, 'removes calendars from the calendar list of {e}; the calendars are kept'),
    ('remove', 'calendar'): (None, 'deletes calendars, as {e}'),
    ('delete', 'delegate'): (None, 'removes mail delegates of {e}'),
    ('delete', 'token'): (None, 'revokes app access tokens of {e}'),
    ('delete', 'guardian'): (None, 'removes Classroom guardians of {e}'),
    ('delete', 'chatmember'): (None, 'removes chat space members, as {e}'),
    ('remove', 'chatmember'): (None, 'removes chat space members, as {e}'),
    ('delete', 'drivefileacl'): (None, 'removes sharing from Drive files, as {e}'),
    ('delete', 'permission'): (None, 'removes sharing from Drive files, as {e}'),
    ('delete', 'calendaracl'): (None, 'removes sharing from calendars of {e}'),
}

# Recovery windows, only where Google's admin help states one.
_USERS_KB, _DRIVE_KB = 'support.google.com/a/answer/1397578', 'support.google.com/a/answer/6052340'
_SHARED_KB, _GMAIL_KB = 'support.google.com/a/answer/7376096', 'support.google.com/a/answer/112445'
UNDO = {
    ('delete', 'user'): f'an admin can restore a deleted user for 20 days ({_USERS_KB})',
    ('delete', 'shareddrive'): f'an admin can restore a deleted shared drive for 25 days ({_SHARED_KB})',
    ('delete', 'message'): f'skips Trash; an admin can restore it with Restore data for 25 days ({_GMAIL_KB})',
    ('delete', 'thread'): f'skips Trash; an admin can restore it with Restore data for 25 days ({_GMAIL_KB})',
    ('trash', 'message'): f'Gmail empties Trash after 30 days ({_GMAIL_KB})',
    ('trash', 'thread'): f'Gmail empties Trash after 30 days ({_GMAIL_KB})',
    ('trash', 'drivefile'): f'Drive empties Trash after 30 days ({_DRIVE_KB})',
    ('purge', 'drivefile'): f'skips Trash; an admin can restore it for 25 days ({_DRIVE_KB})',
    ('empty', 'drivetrash'): f'an admin can restore emptied Trash for 25 days ({_DRIVE_KB})',
}

SECURITY_VERBS = {
    'turnoff2sv': 'turns off 2-Step Verification',
    'forward': 'sets mail forwarding',
    'delegate': 'gives another account access to the mailbox',
    'sendas': 'lets the mailbox send as another address',
    'filter': 'mail filters can forward or delete incoming mail',
}
SECURITY_OBJECTS = {
    'admin': 'grants admin rights',
    'adminrole': 'changes what an admin role can do',
    'sakey': 'service account keys give full API access',
    'svcacct': 'service accounts can act on the tenant',
    'delegate': 'gives another account access to the mailbox',
    'filter': 'mail filters can forward or delete incoming mail',
    'forwardingaddress': 'adds a mail forwarding destination',
    'drivefileacl': 'changes who can open Drive files',
    'permission': 'changes who can open Drive files',
    'calendaracl': 'changes who can see or edit a calendar',
    'backupcode': '2-Step Verification backup codes',
}

PHRASE = {
    'print': 'lists', 'show': 'shows', 'info': 'shows details of', 'list': 'lists', 'report': 'reads audit report',
    'delete': 'deletes', 'del': 'deletes', 'remove': 'removes', 'purge': 'purges', 'wipe': 'wipes',
    'empty': 'empties', 'trash': 'moves to trash', 'obliterate': 'obliterates', 'clear': 'clears',
    'update': 'changes', 'modify': 'modifies', 'create': 'creates', 'add': 'adds', 'move': 'moves',
    'copy': 'copies', 'transfer': 'transfers', 'suspend': 'suspends', 'unsuspend': 'unsuspends',
    'undelete': 'restores', 'sync': 'syncs (adds and removes to match)', 'deprovision': 'deprovisions',
    'get': 'downloads', 'download': 'downloads', 'export': 'exports', 'sendemail': 'sends email',
    'signout': 'signs out', 'forward': 'forwards', 'turnoff2sv': 'turns off 2-Step Verification for',
}

OBJECT_LABEL = {
    'user': 'user account', 'users': 'user accounts', 'drivefile': 'Drive files', 'message': 'Gmail messages',
    'thread': 'Gmail threads', 'group': 'group', 'shareddrive': 'shared drive', 'drivefileacl': 'Drive file sharing',
    'calendaracl': 'calendar sharing', 'license': 'licence', 'alias': 'alias', 'event': 'calendar events',
    'filter': 'Gmail filters', 'delegate': 'mail delegates', 'sendas': 'send-as addresses', 'org': 'org unit',
    'device': 'device', 'deviceuser': 'device user', 'photo': 'profile photo', 'token': 'OAuth tokens',
    'backupcode': '2SV backup codes', 'label': 'Gmail labels', 'drivetrash': 'Drive trash',
    'datastudioasset': 'Looker Studio assets', 'datastudiopermission': 'Looker Studio sharing',
    'chromebrowser': 'Chrome browsers',
}

GAM_NAMES = {'gam', 'gam7', 'gamadv', 'gamadv-xtd3', 'gam.py'}
ECHO_WORDS = {'echo', 'printf', 'write-host', 'write-output', 'rem', 'print', 'cat', 'grep', 'findstr', 'which',
              'where', 'type', 'man', 'select-string', 'get-command'}
PREFIX_WORDS = {'sudo', 'time', 'exec', 'nohup', 'env', 'command', 'call', 'start', 'then', 'do', 'else', '{',
                '!', 'if', 'while', 'until', 'xargs', 'nice', 'timeout', 'caffeinate', 'ssh', 'su', 'bash', 'sh', 'zsh',
                'python', 'python3', 'py', 'cmd', 'powershell', 'pwsh', 'start-process', 'ionice', 'chrt', 'doas', 'runuser'}
# A paste that runs a script (python3 audit.py, bash ./offboard.sh) holds no gam
# commands itself; the script it names is checked instead when it exists here.
SCRIPT_RUNNERS = {'python', 'python3', 'py', 'bash', 'sh', 'zsh', 'pwsh', 'powershell', 'source', '.', 'call'}
SCRIPT_EXTS = ('.py', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd')
SEPARATORS = {';', '&&', '||', '|', '&', '(', ')', ';;', '|&', '{', '}'}
REDIRECTS = {'>', '>>', '<', '>&', '<&', '&>', '&>>', '<<', '<<<', '>|'}

# Local-machine damage. Checked against the parts of a line that are not gam.
LOCAL_RULES = [
    (DESTRUCTIVE, r'\brm\s+(?:-\w*[rR]\w*|--recursive)', 'deletes local files and folders recursively'),
    (DESTRUCTIVE, r'(?i)\b(?:rmdir|rd)\s+/s\b', 'deletes a local folder tree'),
    (DESTRUCTIVE, r'(?i)\bdel\s+(?:.*\s)?/s\b', 'deletes local files in every subfolder'),
    (DESTRUCTIVE, r'(?i)\bRemove-Item\b.*-Recurse', 'deletes a local folder tree'),
    (DESTRUCTIVE, r'(?i)\bformat\s+[a-z]:', 'formats a disk'),
    (DESTRUCTIVE, r'(?i)\bdiskpart\b', 'runs the Windows disk partitioner'),
    (DESTRUCTIVE, r'\bmkfs(?:\.\w+)?\b|\bwipefs\b|\bshred\b', 'erases a disk or file beyond recovery'),
    (DESTRUCTIVE, r'\bdd\s+.*\bof=/dev/', 'writes raw data over a disk'),
    (DESTRUCTIVE, r'>\s*/dev/(?:sd|disk|nvme|hd)', 'writes raw data over a disk'),
    (DESTRUCTIVE, r'(?i)\bdiskutil\s+(?:erase\w*|zeroDisk|secureErase|partitionDisk|reformat)', 'erases a disk'),
    (DESTRUCTIVE, r'(?i)\b(?:Clear-Disk|Format-Volume|Remove-Partition|Initialize-Disk)\b', 'erases a disk'),
    (DESTRUCTIVE, r'(?i)\bcipher\s+/w', 'overwrites free disk space'),
    (DESTRUCTIVE, r'(?i)\breg\s+delete\b', 'deletes Windows registry keys'),
    (DESTRUCTIVE, r'(?i)\bvssadmin\s+delete\b', 'deletes Windows shadow copies (backups)'),
    (CHANGES, r'\brm\s+', 'deletes local files'),
    (CHANGES, r'(?i)(?:^|[\s;&|])del\s+\S', 'deletes local files'),
    (CHANGES, r'(?i)\bRemove-Item\b', 'deletes local files'),
    (CHANGES, r'(?i)\breg\s+add\b', 'changes the Windows registry'),
    (SUSPICIOUS, r'(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b', 'downloads a script and runs it'),
    (SUSPICIOUS, r'(?i)\b(?:iex|Invoke-Expression)\b', 'runs text as PowerShell code'),
    (SUSPICIOUS, r'(?i)(?:^|\s)-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}', 'runs a hidden (encoded) PowerShell command'),
    (SUSPICIOUS, r'(?i)\bFromBase64String\b|\bbase64\s+(?:-d|--decode|-D)\b', 'decodes hidden content'),
    (UNKNOWN, r'(?:^|[\s;&|(])eval\s', 'runs text built at runtime as a command'),
]
# gam named inside a quoted string handed to another program: bash -c "gam ...", "$(gam ...)"
FD_REDIRECT = re.compile(r'(^|\s)\d(?=[<>])')
# Commands whose arguments are file paths, never commands to run: a gam path or a
# variable holding one after these ([[ -x $GAMDIR/gam ]], cp -a "$GAMDIR" ...) is data.
FILE_COMMANDS = {'[', '[[', 'test', 'cp', 'mv', 'ls', 'ln', 'rm', 'rmdir', 'mkdir', 'cd', 'pushd', 'chmod', 'chown',
                 'touch', 'stat', 'file', 'du', 'dirname', 'basename', 'realpath', 'readlink', 'tar', 'unzip', 'zip',
                 'shasum', 'sha256sum', 'md5', 'md5sum', 'diff', 'rsync', 'scp', 'test-path', 'copy-item', 'move-item',
                 'remove-item', 'get-item', 'get-childitem', 'robocopy', 'xcopy', 'copy', 'move', 'del', 'dir', 'mklink'}
GAM_INSIDE = re.compile(r'(?:^|[\s"\'(=])(?:\S*[/\\])?gam(?:\.exe|\.py)?\s+[A-Za-z]')
CREDENTIAL_RE = re.compile(r'(?i)oauth2(?:service)?\.(?:txt|json)|client_secrets\.json')
NETWORK_COMMANDS = {'curl', 'wget', 'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm', 'nc', 'ncat', 'scp', 'sftp',
                    'ftp', 'send-mailmessage', 'rsync', 'rclone', 'bitsadmin', 'certutil'}


class Dyn(str):
    """A token whose value is only known when the script runs, such as $USER or an f-string field."""


@dataclass
class Finding:
    """One thing the script would do, located by file and line."""
    file: str
    line: int
    level: int
    what: str
    command: str = ''
    security: str = ''
    note: str = ''
    undo: str = ''
    docs: str = ''

    def as_dict(self):
        """Serialise for --json, with the level spelled out."""
        d = asdict(self)
        d['level'] = LEVEL_NAMES[self.level]
        return d


def low(tok):
    """Lower-cased token, or None for a missing or runtime token."""
    if tok is None or isinstance(tok, Dyn):
        return None
    return tok.strip().lower()


def norm(tok):
    """GAM's normalisation of a keyword: lower case, underscores and hyphens dropped."""
    w = low(tok)
    return w.replace('_', '').replace('-', '') if w is not None else None


def choose(tok, choices, aliases=None):
    """Match a token the way GAM's getChoice does, returning the canonical word or None."""
    c = low(tok)
    if c is None:
        return None
    aliases = aliases or {}
    c = aliases.get(c, c)
    if c not in choices:
        c = c.replace('_', '').replace('-', '')
        c = aliases.get(c, c)
    return c if c in choices else None


def short(tokens, limit=140):
    """Render tokens back into a readable, truncated command line."""
    text = ' '.join(str(t) for t in tokens)
    return text if len(text) <= limit else text[:limit - 3] + '...'


def count_rows(path_text, base_dirs):
    """Count data rows in a CSV next to the script or in the working directory.

    Returns None when the file cannot be found, which callers report as
    unknown rather than zero.
    """
    if path_text is None or isinstance(path_text, Dyn):
        return None
    candidates = [path_text]
    if ':' in path_text and not re.match(r'^[A-Za-z]:[\\/]', path_text):
        candidates.append(path_text.rsplit(':', 1)[0])
    for cand in candidates:
        for base in base_dirs:
            p = (base / cand) if not Path(cand).is_absolute() else Path(cand)
            if p.is_file():
                with p.open(encoding='utf-8-sig', errors='replace', newline='') as f:
                    return max(sum(1 for _ in csv.reader(f)) - 1, 0)
    return None


class Tables:
    """The GAM7 dispatch tables plus the verb sets of the older versions."""

    def __init__(self, verbs_dir=VERBS_DIR):
        g7 = json.loads((verbs_dir / 'gam7.json').read_text(encoding='utf-8'))
        self.version = g7['gam_version']
        self.t = g7['tables']
        self.cmd = g7['cmd']
        self.config_vars = set(g7['config_variables'])
        wiki = verbs_dir / 'wiki.json'
        self.docs = json.loads(wiki.read_text(encoding='utf-8'))['pages'] if wiki.is_file() else {}
        self.older = []
        for name, label in (('gamadv-xtd3.json', 'GAMADV-XTD3'), ('legacy-gam.json', 'legacy GAM')):
            data = json.loads((verbs_dir / name).read_text(encoding='utf-8'))
            keys = {(r[0], norm(r[1]), norm(r[2]) if r[2] else None) for r in data['pairs']}
            self.older.append((f"{label} {data['gam_version']}", keys))
        c = self.cmd
        self.user_types = set(c['USER_ENTITIES'])
        self.cros_types = set(c['CROS_ENTITIES'])
        self.selectors = set(c['BASE_ENTITY_SELECTORS'] + c['USER_ENTITY_SELECTORS'] + c['CROS_ENTITY_SELECTORS']
                             + c['USER_CSVDATA_ENTITY_SELECTORS'] + c['CROS_CSVDATA_ENTITY_SELECTORS'])

    def older_version(self, scope, verb_tok, obj_tok):
        """Name the older GAM that accepts this command, or None."""
        v, o = norm(verb_tok), norm(obj_tok)
        for label, keys in self.older:
            if (scope, v, o) in keys or (scope, v, None) in keys:
                return label
        return None


class GamParser:
    """Turn one gam argument list into findings, following GAM7's parse order."""

    def __init__(self, tables):
        self.tb = tables

    # ----- entry point

    def parse(self, args, ctx, line):
        """Classify gam arguments (everything after the gam executable)."""
        a = list(args)
        results = []
        i = 0
        if low(self._tok(a, i)) == 'loop':
            return self._wrapper('loop', a, i, ctx, line)
        i, pre_level, pre_note = self._preamble(a, i)
        t = self._tok(a, i)
        if t is None:
            if pre_level > READ:
                results.append(Finding(ctx.file, line, pre_level, 'changes GAM settings', short(['gam'] + a), note=pre_note))
            elif not a:
                results.append(Finding(ctx.file, line, UNKNOWN, 'gam with no arguments visible', 'gam'))
            else:
                results.append(Finding(ctx.file, line, READ, 'selects a GAM configuration section', short(['gam'] + a)))
            return results
        if isinstance(t, Dyn):
            return [Finding(ctx.file, line, UNKNOWN, 'the gam command itself is decided at runtime',
                            short(['gam'] + a))]
        tb = self.tb.t
        word = low(t)
        if word == 'loop' or word in tb['BATCH_CSV_COMMANDS']:
            results = self._wrapper(word, a, i, ctx, line)
        elif word in tb['MAIN_COMMANDS']:
            scope = self._report_scope(a[i + 1:]) if word == 'report' else ''
            results = [self._finding(ctx, line, a, 'main', word, None, a[i + 1:], scope)]
        elif word in tb['MAIN_COMMANDS_WITH_OBJECTS']:
            results = [self._with_object(ctx, line, a, i, 'main', tb['MAIN_COMMANDS_WITH_OBJECTS'],
                                         tb['MAIN_COMMANDS_OBJ_ALIASES'], '')]
        elif choose(t, tb['COMMANDS_MAP'], tb['COMMANDS_ALIASES']):
            results = [self._subcommand(ctx, line, a, i, choose(t, tb['COMMANDS_MAP'], tb['COMMANDS_ALIASES']))]
        else:
            results = [self._entity(ctx, line, a, i)]
        if pre_level > READ:
            for r in results:
                r.level = max(r.level, pre_level)
                r.note = '; '.join(n for n in (r.note, pre_note) if n)
        return results

    # ----- grammar pieces

    def _report_scope(self, rest):
        """Who a gam report covers, so a one-user report is not described as tenant-wide.

        GAM7 doReport narrows user reports with user <x>|all, ou|org|orgunit <path> or
        select <entity>, the last one given winning; report usage user also takes a bare
        user selector. Customer reports are always tenant-wide."""
        kind = norm(self._tok(rest, 0))
        k = 2 if kind == 'usage' else 1
        if kind in ('customer', 'customers', 'domain', 'usageparameters') or kind == 'usage' and norm(self._tok(rest, 1)) == 'customer':
            return 'for the whole tenant'
        scope = 'for the whole tenant'
        while k < len(rest):
            w, v = norm(rest[k]), self._tok(rest, k + 1)
            if v is not None and w == 'user':
                scope = 'for the whole tenant' if norm(v) == 'all' else f'for user {v}'
            elif v is not None and w in ('ou', 'org', 'orgunit'):
                scope = f'for the users in OU {v}'
            elif w == 'select' or kind == 'usage' and w in ('csv', 'csvfile', 'file', 'csvdata'):
                picked = rest[k + 1:k + 3] if w == 'select' else rest[k:k + 2]
                scope = f'for the users selected by {short(picked, 60)}'
            else:
                k += 1
                continue
            k += 2
        return scope

    @staticmethod
    def _value_after(rest, keyword):
        """True/False for an on/off value after keyword, None when absent or decided at runtime."""
        at = next((k for k, t in enumerate(rest) if norm(t) == keyword), None)
        v = norm(rest[at + 1]) if at is not None and at + 1 < len(rest) else None
        return True if v in TRUE_VALUES else False if v in FALSE_VALUES else None

    @staticmethod
    def _shown(tok):
        if isinstance(tok, Dyn):
            return f'{tok} (from each row)' if str(tok).startswith('~') else f'{tok} (set at runtime)'
        return str(tok)

    @staticmethod
    def _tok(a, i):
        return a[i] if 0 <= i < len(a) else None

    def _preamble(self, a, i):
        """Skip select/config/redirect/etc. Returns (index, level, note) for gam.cfg writes."""
        level, notes = READ, []
        booleans = {'true', 'false', 'on', 'off', 'yes', 'no', '1', '0', 'enable', 'disable'}
        while i < len(a):
            w = low(a[i])
            if w == 'select':
                i += 2
                if i >= len(a):
                    level, notes = CHANGES, notes + ['saves the selected section as the default in gam.cfg']
                while low(self._tok(a, i)) in ('save', 'verify'):
                    if low(a[i]) == 'save':
                        level, notes = CHANGES, notes + ['saves the selected section as the default in gam.cfg']
                    i += 1
                    if low(self._tok(a, i)) == 'variables':
                        i += 2
            elif w in ('selectfilter', 'selectoutputfilter', 'selectinputfilter', 'multiprocessexit'):
                i += 2
            elif w == 'showsections':
                i += 1
            elif w == 'config':
                i += 1
                while i < len(a):
                    x = low(a[i])
                    if x == 'save':
                        level, notes = CHANGES, notes + ['writes settings into gam.cfg']
                        i += 1
                    elif x == 'verify':
                        i += 1
                    elif choose(a[i], self.tb.config_vars):
                        i += 1
                        if low(self._tok(a, i)) == '=':
                            i += 1
                        i += 1
                    else:
                        break
            elif w == 'redirect':
                kind = low(self._tok(a, i + 1))
                i += 3
                if kind == 'csv':
                    while i < len(a):
                        x = low(a[i])
                        if x in ('multiprocess', 'append', 'noheader', 'delayopen'):
                            i += 1
                        elif x in ('charset', 'columndelimiter', 'quotechar', 'sortheaders', 'timestampcolumn'):
                            i += 2
                        elif x in ('noescapechar', 'transpose'):
                            i += 2 if low(self._tok(a, i + 1)) in booleans else 1
                        else:
                            break
                    if low(self._tok(a, i)) == 'todrive':
                        level, notes = CHANGES, notes + ['uploads the output to a Google Sheet in your Drive']
                        i += 1
                        while (low(self._tok(a, i)) or '').startswith('td'):
                            i += 2
                else:
                    while low(self._tok(a, i)) in ('multiprocess', 'append'):
                        i += 1
            else:
                break
        return i, level, '; '.join(dict.fromkeys(notes))

    def _wrapper(self, word, a, i, ctx, line):
        """batch/tbatch follow a file of commands; csv/loop repeat one inner gam command per CSV row."""
        file_tok = self._tok(a, i + 1)
        if word in ('batch', 'tbatch'):
            return ctx.follow_batch(file_tok, line, short(['gam'] + a))
        if word == 'csvtest':
            return [Finding(ctx.file, line, READ, 'previews the commands a CSV would run', short(['gam'] + a))]
        inner_at = next((j for j in range(i + 2, len(a)) if low(a[j]) == 'gam'), None)
        if inner_at is None:
            return [Finding(ctx.file, line, UNKNOWN, f'gam {word} without a visible inner gam command',
                            short(['gam'] + a))]
        rows = count_rows(file_tok, ctx.base_dirs)
        filtered = any(norm(t) in ('matchfield', 'skipfield') for t in a[i + 2:inner_at])
        if rows is not None and filtered:
            where = f'once per row of {file_tok} that passes its matchfield/skipfield ({rows} rows before filtering)'
        else:
            where = f'once per row of {file_tok}' + (f' ({rows} rows)' if rows is not None else ' (file not provided, row count unknown)')
        # ~field and ~~field~~ are filled from each CSV row
        inner = [Dyn(t) if isinstance(t, str) and '~' in t and not isinstance(t, Dyn) else t for t in a[inner_at + 1:]]
        results = self.parse(inner, ctx, line)
        for r in results:
            r.what = f'{r.what}, {where}'
            r.command = short(['gam'] + a)
        return results

    def _with_object(self, ctx, line, a, i, scope, table, aliases, entity):
        """verb <object> forms: gam delete user x, gam <users> delete drivefile ..."""
        verb = choose(a[i], table)
        obj_tok = self._tok(a, i + 1)
        obj = choose(obj_tok, table[verb][1], aliases)
        if obj is None and scope == 'user' and verb == 'print' and not isinstance(obj_tok, Dyn):
            # GAM7 defaults the object to users here without consuming the next word
            return self._finding(ctx, line, a, scope, verb, 'user', a[i + 1:], entity)
        if obj is None:
            if isinstance(obj_tok, Dyn):
                return Finding(ctx.file, line, UNKNOWN, f"'{verb}' on something decided at runtime ({obj_tok})",
                               short(['gam'] + a))
            return self._unrecognised(ctx, line, a, scope, a[i], obj_tok)
        rest = a[i + 2:]
        named = ''
        if scope == 'main' and not entity and rest and verb not in ('print', 'show') \
                and norm(rest[0]) not in VALUE_KEYWORDS | {'devicesn'}:
            named = self._shown(rest[0])
        return self._finding(ctx, line, a, scope, verb, obj, rest, entity, named)

    def _subcommand(self, ctx, line, a, i, cmd):
        """oauth, audit, calendars, course(s) and resource(s), which each have their own sub-grammar."""
        tb = self.tb.t
        full = short(['gam'] + a)
        if cmd == 'oauth':
            sub = choose(self._tok(a, i + 1), tb['OAUTH2_SUBCOMMANDS'], tb['OAUTH2_SUBCOMMAND_ALIASES'])
            if not sub:
                return self._unrecognised(ctx, line, a, 'oauth', self._tok(a, i + 1), None)
            f = self._finding(ctx, line, a, 'oauth', sub, None, a[i + 2:], "GAM's own saved credentials")
            if sub == 'export':
                f.security = "copies GAM's credentials to a file"
            return f
        if cmd == 'audit':
            objs = tb['AUDIT_SUBCOMMANDS_WITH_OBJECTS'].get(low(self._tok(a, i + 1)) or '', {})
            sub = choose(self._tok(a, i + 2), objs)
            if not sub:
                return self._unrecognised(ctx, line, a, 'audit', self._tok(a, i + 1), self._tok(a, i + 2))
            return self._finding(ctx, line, a, 'audit', sub, 'monitor', a[i + 3:], '')
        if cmd == 'calendars':
            oldacl_aliases = tb['CALENDAR_OLDACL_SUBCOMMAND_ALIASES']
            obj_aliases = tb['CALENDARS_SUBCOMMANDS_OBJECT_ALIASES']
            for j in range(i + 2, min(len(a), i + 12)):
                if choose(a[j], tb['CALENDAR_SUBCOMMANDS']):
                    return self._finding(ctx, line, a, 'calendar', choose(a[j], tb['CALENDAR_SUBCOMMANDS']), None,
                                         a[j + 1:], f'calendar {a[i + 1]}')
                old = choose(a[j], tb['CALENDAR_OLDACL_SUBCOMMANDS'], oldacl_aliases)
                if old:
                    obj = choose(self._tok(a, j + 1), ['calendaracl', 'event'], obj_aliases) or 'calendaracl'
                    return self._finding(ctx, line, a, 'calendar', old, obj, a[j + 1:], f'calendar {a[i + 1]}')
                if choose(a[j], tb['CALENDARS_SUBCOMMANDS_WITH_OBJECTS']):
                    return self._with_object(ctx, line, a, j, 'calendar', tb['CALENDARS_SUBCOMMANDS_WITH_OBJECTS'],
                                             obj_aliases, f'calendar {a[i + 1]}')
            return self._unrecognised(ctx, line, a, 'calendar', self._tok(a, i + 2), self._tok(a, i + 3))
        if cmd in ('course', 'courses'):
            for j in range(i + 2, min(len(a), i + 12)):
                sub = choose(a[j], tb['COURSE_SUBCOMMANDS'], tb['COURSE_SUBCOMMAND_ALIASES'])
                if sub:
                    return self._finding(ctx, line, a, 'course', sub, None, a[j + 1:], f'course {a[i + 1]}')
            return self._unrecognised(ctx, line, a, 'course', self._tok(a, i + 2), None)
        # resource / resources
        table = tb['RESOURCE_SUBCOMMANDS_WITH_OBJECTS']
        for j in range(i + 2, min(len(a), i + 12)):
            if choose(a[j], table, tb['RESOURCE_SUBCOMMAND_ALIASES']):
                verb = choose(a[j], table, tb['RESOURCE_SUBCOMMAND_ALIASES'])
                obj = choose(self._tok(a, j + 1), table[verb][1], tb['RESOURCE_SUBCOMMANDS_OBJECT_ALIASES'])
                if obj:
                    return self._finding(ctx, line, a, 'resource', verb, obj, a[j + 2:], f'resource {a[i + 1]}')
        return Finding(ctx.file, line, UNKNOWN, 'unrecognised resource command', full)

    def _entity(self, ctx, line, a, i):
        """gam <user or ChromeOS entity> <verb> ..."""
        tb, c = self.tb.t, self.tb.cmd
        t = a[i]
        sel = choose(t, self.tb.selectors)
        if sel:
            if sel == 'all':
                sub = low(self._tok(a, i + 1)) or '?'
                kind = 'cros' if sub == 'cros' else 'user'
                entity, start = f'all {ALL_SUBTYPES.get(sub, sub)} in the tenant', i + 2
            elif sel in ('datafile', 'csvdatafile', 'csvkmd'):
                sub = low(self._tok(a, i + 1)) or ''
                kind = 'cros' if sub.startswith('cros') else 'user'
                entity, start = self._listed(sub or 'entries', self._tok(a, i + 2), ctx), i + 3
            elif sel in ('csvdata', 'croscsvdata', 'csvsubkey'):
                kind = 'cros' if sel.startswith('cros') else 'user'
                entity, start = 'the entries from the surrounding CSV', i + 1
            else:
                kind = 'cros' if sel.startswith('cros') else 'user'
                entity, start = self._listed('devices' if kind == 'cros' else 'users', self._tok(a, i + 1), ctx), i + 2
        else:
            et = choose(t, self.tb.user_types | self.tb.cros_types, c['ENTITY_ALIAS_MAP'])
            if not et:
                return self._unrecognised(ctx, line, a, 'main', t, self._tok(a, i + 1))
            kind = 'cros' if et in self.tb.cros_types else 'user'
            if et == 'oauthuser':
                entity, start = 'the GAM admin account', i + 1
            else:
                entity, start = self._describe(et, self._tok(a, i + 1)), i + 2
        if kind == 'user':
            flat, objs = tb['USER_COMMANDS'], tb['USER_COMMANDS_WITH_OBJECTS']
            valiases, oaliases = tb['USER_COMMANDS_ALIASES'], tb['USER_COMMANDS_OBJ_ALIASES']
        else:
            flat, objs = tb['CROS_COMMANDS'], tb['CROS_COMMANDS_WITH_OBJECTS']
            valiases, oaliases = {}, tb['CROS_COMMANDS_OBJ_ALIASES']
        verbs = set(flat) | set(objs)
        for j in range(start, min(len(a), start + 12)):
            verb = choose(a[j], verbs, valiases)
            if verb:
                break
        else:
            nxt = self._tok(a, start)
            if isinstance(nxt, Dyn):
                return Finding(ctx.file, line, UNKNOWN, f'action on {entity} is decided at runtime ({nxt})',
                               short(['gam'] + a))
            return self._unrecognised(ctx, line, a, kind, nxt, self._tok(a, start + 1))
        if verb in flat:
            return self._finding(ctx, line, a, kind, verb, None, a[j + 1:], entity)
        return self._with_object(ctx, line, a[:j] + [verb] + a[j + 1:], j, kind, objs, oaliases, entity)

    def _listed(self, what, file_tok, ctx):
        rows = count_rows(file_tok, ctx.base_dirs)
        count = f'{rows} rows' if rows is not None else 'file not provided, count unknown'
        return f'every {what} listed in {file_tok} ({count})'

    @staticmethod
    def _describe(et, value):
        shown = value if value is not None and not isinstance(value, Dyn) else f'{value} (set at runtime)'
        return {
            'user': f'user {shown}', 'users': f'users {shown}', 'group': f'members of group {shown}',
            'groups': f'members of groups {shown}', 'ou': f'users in OU {shown}',
            'ou_and_children': f'users in OU {shown} and every OU below it', 'query': f'users matching {shown}',
            'cros': f'ChromeOS device {shown}', 'cros_ou': f'ChromeOS devices in OU {shown}',
            'domains': f'users in domain {shown}', 'licenses': f'users holding licence {shown}',
        }.get(et, f'{et} {shown}')

    # ----- classification

    def _finding(self, ctx, line, a, scope, verb, obj, rest, entity, named=''):
        """Build the finding for a recognised command, including argument-dependent levels.

        named is the object the command acts on (gam delete user <x>), shown after the
        object label so a reviewer can check the target, not just the kind of change."""
        if scope == 'user' and verb == 'forward' and obj is None and norm(self._tok(rest, 0)) in GMAIL_ITEMS:
            # setForward hands forward messages|threads to forwardMessagesThreads
            obj, rest = GMAIL_ITEMS[norm(rest[0])], rest[1:]
        words = {norm(t) for t in rest if not isinstance(t, Dyn)}
        no_target = obj in ('message', 'thread', 'orphans', 'chatmember') or verb == 'issuecommand' or (scope, verb, obj) == ('main', 'sync', 'device')
        flags = self._flags(rest, positional=not no_target)
        level = SCOPE_LEVEL.get((scope, verb))
        if scope == 'audit':
            level = VERB_LEVEL.get(verb)
        if level is None:
            level = VERB_LEVEL.get(verb, UNKNOWN)
        notes, security, undo, what = [], '', UNDO.get((verb, obj), ''), None
        runtime = any(isinstance(t, Dyn) for t in rest)
        key, dry = (scope, verb, obj), False
        if verb in NOTES:
            notes.append(NOTES[verb])
        if scope == 'user' and (verb, obj) in USER_RELATION:
            forced, template = USER_RELATION[(verb, obj)]
            level = forced if forced is not None else level
            what = template.format(e=entity or 'the user')
        if verb == 'sync' and 'addonly' in flags and 'removeonly' not in words:
            level, notes = CHANGES, notes + ['addonly: adds, never removes']
        if key in (('main', 'update', 'group'), ('main', 'update', 'cigroup')) and not rest:
            return self._unrecognised(ctx, line, a, scope, None, None)  # 'gam update group' with no group: incomplete, not a crash
        if key in (('main', 'update', 'group'), ('main', 'update', 'cigroup')):
            # The group can be a multi-word selector (csvkmd FILE keyfield F ...), so the
            # action is the first membership word after it, not always the second token.
            at = next((k for k in range(1, min(len(rest), 12)) if isinstance(rest[k], Dyn)
                       or norm(rest[k]) in GROUP_MEMBER_ACTIONS), 1)
            action = self._tok(rest, at)
            group = rest[0] if at == 1 else f'the groups selected by {short(rest[:at], 60)}'
            if isinstance(action, Dyn):
                level, what = UNKNOWN, f'changes group {group}; which change is decided at runtime ({action})'
            elif norm(action) in GROUP_MEMBER_ACTIONS:
                level, phrase = GROUP_MEMBER_ACTIONS[norm(action)]
                what = f'{phrase} group {group}'
                if norm(action) == 'sync':
                    if 'addonly' in flags and 'removeonly' not in words:
                        level = CHANGES
                    else:
                        notes.append('removes every member not in the list')
            else:
                key = None  # a settings update: preview is not accepted there
        if verb == 'purge' and obj == 'event':
            notes.append('deletes the matched events permanently even without doit, though GAM prints "Not Deleted"')
            undo = 'none: the events skip the calendar trash'
        if obj == 'drivefile' and verb == 'delete':
            if 'purge' in words:
                undo = UNDO[('purge', 'drivefile')]
                notes.append('purge deletes permanently')
            elif 'untrash' in flags:
                level, what = CHANGES, f'restores Drive files from Trash, for {entity}'
            else:
                undo = UNDO[('trash', 'drivefile')]
                notes.append('without purge, GAM moves the files to Trash')
        if verb == 'update' and (obj in ('mobile', 'device', 'deviceuser', 'cros') or scope == 'cros'):
            # MOBILE_ACTION_CHOICE_MAP, DEVICE_ACTION_CHOICES, DEVICE_USER_ACTION_CHOICES, CROS_ACTION_CHOICE_MAP
            at = next((k for k, t in enumerate(rest) if low(t) == 'action'), None)
            action = self._tok(rest, at + 1) if at is not None else None
            if isinstance(action, Dyn):
                level, notes = UNKNOWN, notes + [f'the device action is decided at runtime ({action})']
            elif action and 'wipe' in norm(action) and 'cancel' not in norm(action):
                level, notes = DESTRUCTIVE, notes + [f'action {action} erases the device']
            elif action and norm(action).startswith('deprovision'):
                level, notes = DESTRUCTIVE, notes + ['deprovisions the ChromeOS device']
        # A device named directly gets doit from GAM itself; only a query (or devicesn) needs it
        named_device = (obj in ('mobile', 'device', 'deviceuser') and not words & {'query', 'devicesn'}
                        and not (low(self._tok(rest, 0)) or '').startswith('query:'))
        if key in DOIT_GATED and not (obj in ('message', 'thread') and 'ids' in words) and not named_device:
            if 'doit' in flags:
                if key in MAX_TO_ONE and not any(w.startswith('maxto') for w in words):
                    notes.append(f'GAM skips any user where more than 1 item matches, unless max_to_{verb} is given')
            elif runtime:
                notes.append('runs only if a value set at runtime supplies doit')
            else:
                level, undo, dry = READ, '', True
                notes.append('no doit: GAM counts what matches and changes nothing')
        if key in PREVIEW_ABLE and 'preview' in flags:
            level, undo, dry = READ, '', True
            notes.append('preview: GAM lists what it would do and changes nothing')
        if verb == 'issuecommand':
            at = next((k for k, t in enumerate(rest) if low(t) == 'command'), None)
            chosen = choose(self._tok(rest, at + 1), self.tb.t['CROS_COMMAND_CHOICE_MAP']) if at is not None else None
            if chosen in ('wipeusers', 'remotepowerwash'):
                if 'doit' in flags or runtime:
                    level, notes = DESTRUCTIVE, notes + [f'{chosen} erases the device']
                else:
                    level, dry = READ, True
                    notes.append(f'{chosen} erases the device, but GAM refuses it without doit')
            elif chosen:
                notes.append(f'sends {chosen} to the device')
            else:
                level, notes = DESTRUCTIVE, notes + ['device command not readable; treated as a wipe']
        if 'todrive' in words:
            level = max(level, CHANGES)
            notes.append('uploads the output to a Google Sheet in your Drive')
        if verb in ('update', 'create', 'add') and obj == 'user':
            if 'password' in words:
                security = 'sets the account password'
            if 'suspended' in words:
                state = self._value_after(rest, 'suspended')
                notes.append({True: 'suspends the account', False: 'unsuspends the account'}.get(state, 'can suspend the account'))
            if words & {'ou', 'org', 'orgunit'}:
                notes.append('moves the account to another OU, which can change its policies and licences')
        if verb == 'forward' and obj in ('message', 'thread'):
            security = 'sends copies of existing mail to another address'
        elif verb == 'forward' and obj is None and self._value_after(['forward'] + list(rest), 'forward') is False:
            what = f'turns off mail forwarding, for {entity}'
        elif verb in SECURITY_VERBS:
            security = SECURITY_VERBS[verb]
        elif obj in SECURITY_OBJECTS and (level > READ or obj == 'backupcode'):
            security = SECURITY_OBJECTS[obj]
        if obj in ('drivefileacl', 'permission', 'calendaracl') and 'anyone' in words:
            security = 'shares with anyone who has the link'
        if what is None:
            phrase = PHRASE.get(verb, verb)
            target = OBJECT_LABEL.get(obj, obj) if obj else ''
            what = ' '.join(p for p in (phrase, target) if p)
            if named:
                what = f'{what} {named}'
            if (verb, obj) == ('transfer', 'drive') and rest:
                what = f'{what} to {self._shown(rest[0])}'
            if entity:
                what = f'{what}, for {entity}' if not entity.startswith('for ') else f'{what}, {entity}'
        if dry:
            what = f'dry run, would have: {what}'
        return Finding(ctx.file, line, level, what, short(['gam'] + list(a)), security, '; '.join(notes),
                       undo, self.tb.docs.get(f'{scope} {verb} {obj or ""}'.strip(), ''))

    @staticmethod
    def _flags(rest, positional=True):
        """Words in option position: not the positional target (a group, a file id) when the command has one,
        and not the value after a VALUE_KEYWORD. Gmail, issuecommand and collect orphans have no target,
        so their first word is already an option (doit can come first: _getMessageSelectParameters)."""
        flags, k = set(), 1 if positional and norm(rest[0] if rest else None) not in VALUE_KEYWORDS else 0
        while k < len(rest):
            w = norm(rest[k])
            if w in VALUE_KEYWORDS:
                k += 2  # the keyword's value is data, even when it looks like a keyword
                continue
            if w is not None:
                flags.add(w)
            k += 1
        return flags

    def _unrecognised(self, ctx, line, a, scope, verb_tok, obj_tok):
        """GAM7 would reject this; say so, and name an older GAM that accepts it."""
        older = self.tb.older_version(scope, verb_tok, obj_tok)
        full = short(['gam'] + a)
        if older:
            level = VERB_LEVEL.get(norm(verb_tok), UNKNOWN)
            what = f'{verb_tok} {obj_tok or ""}'.strip()
            return Finding(ctx.file, line, level, f"'{what}' (older GAM syntax)", full,
                           note=f'written for {older}; GAM7 {self.tb.version} does not accept it and will stop with an error')
        if verb_tok is None:
            return Finding(ctx.file, line, UNKNOWN, 'incomplete gam command (it stops before the action)', full)
        return Finding(ctx.file, line, UNKNOWN, f"not a command GAM7 {self.tb.version} recognises ('{verb_tok}')", full)


# ----- script readers


@dataclass
class Context:
    """Per-file state shared by the readers: where relative files resolve, and batch-file recursion."""
    file: str
    base_dirs: list
    checker: 'Checker'
    depth: int = 0

    def follow_batch(self, file_tok, line, command):
        """Check the commands inside a gam batch/tbatch file, if it was provided."""
        if file_tok is None or isinstance(file_tok, Dyn) or file_tok == '-':
            return [Finding(self.file, line, UNKNOWN, 'runs a batch file whose name is decided at runtime', command)]
        for base in self.base_dirs:
            p = base / file_tok
            if p.is_file():
                if self.depth >= 3:
                    return [Finding(self.file, line, UNKNOWN, f'batch files nested too deeply at {file_tok}', command)]
                inner = self.checker.check_file(p, depth=self.depth + 1, lang='gambatch')
                for f in inner:
                    f.note = '; '.join(n for n in (f.note, f'from batch file run at {self.file} line {line}') if n)
                return inner or [Finding(self.file, line, READ, f'runs batch file {file_tok}, which holds no commands', command)]
        return [Finding(self.file, line, UNKNOWN, f'runs every gam command in {file_tok}, which was not provided',
                        command, note='check that file too: gamcheck.py ' + file_tok)]

    def follow_script(self, script_tok, line, command):
        """Check a script the line runs (python3 x.py, bash x.sh), if it exists on this computer.

        ~ and the home-folder variables are expanded to the checker's own home folder, which is
        right when the paste is checked on the machine that will run it. Any other variable is
        reported as decided at runtime.
        """
        home = str(Path.home())
        path = re.sub(r'^~(?=[\\/]|$)|\$\{?HOME\}?\b|%USERPROFILE%|\$env:USERPROFILE\b', lambda m: home, script_tok, flags=re.I)
        if re.search(r'\$|%[^%\s]+%', path):
            return [Finding(self.file, line, UNKNOWN, 'runs a script whose path is decided at runtime', command)]
        cands = [Path(path)] if Path(path).is_absolute() else [base / path for base in self.base_dirs]
        p = next((c for c in cands if c.is_file()), None)
        if p is None:
            return [Finding(self.file, line, UNKNOWN, f'runs {script_tok}, which was not provided', command,
                            note='check that file too: gamcheck.py ' + script_tok)]
        if self.depth >= 3:
            return [Finding(self.file, line, UNKNOWN, f'scripts nested too deeply at {p.name}', command)]
        inner = self.checker.check_file(p, depth=self.depth + 1)
        for f in inner:
            f.note = '; '.join(n for n in (f.note, f'from {p.name} run at {self.file} line {line}') if n)
        if not any(f.command.startswith('gam') for f in inner):
            inner.append(Finding(self.file, line, UNKNOWN, f'runs {p.name}, where no gam commands were found', command,
                                 note='if that script does run gam, the checker could not see how'))
        return inner


def _gam_name(tok, gam_vars, wrappers):
    """True when a token names the gam executable, a variable holding its path, or a wrapper function."""
    if tok is None:
        return False
    raw = str(tok).strip('`"\'')
    if raw in wrappers:
        return True
    var = re.fullmatch(r'\$\{?([A-Za-z_]\w*)\}?|%([A-Za-z_]\w*)%|\$env:([A-Za-z_]\w*)', raw)
    if var:
        name = (var.group(1) or var.group(2) or var.group(3)).lower()
        return name in gam_vars or 'gam' in name
    base = re.split(r'[\\/]', raw)[-1].lower()
    if base.endswith('.exe'):
        base = base[:-4]
    return base in GAM_NAMES


def _dynamic(tok, lang):
    """Mark shell, PowerShell and batch variables as runtime tokens."""
    if lang == 'python':
        return tok
    if re.search(r'\$|%[^%\s]+%|%%\w|`|@args', tok):
        return Dyn(tok)
    return tok


def _logical_lines(text, lang):
    """Join continuation lines and drop comments, keeping the first physical line number."""
    if lang == 'powershell':
        text = re.sub(r'<#.*?#>', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)
    cont = {'shell': '\\', 'gambatch': '\\', 'powershell': '`', 'batch': '^'}[lang]
    out, buf, start = [], '', None
    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.rstrip()
        if start is None:
            start = n
        if stripped.endswith(cont) and not stripped.endswith(cont * 2):
            buf += stripped[:-1] + ' '
            continue
        buf += raw
        out.append((start, buf))
        buf, start = '', None
    if buf:
        out.append((start, buf))
    return out


def _tokenise(line, lang):
    """Split a line into words and shell punctuation; unbalanced quotes fall back to whitespace."""
    posix = lang in ('shell', 'gambatch')
    # shlex splits 2>&1 into 2, >&, 1 and the redirect is dropped later, so a
    # file-descriptor number glued to > or < is removed first; else "2" reads as an argument
    line = FD_REDIRECT.sub(r'\1', line)
    try:
        lex = shlex.shlex(line, posix=posix, punctuation_chars=';&|()<>')
        lex.whitespace_split = True
        lex.commenters = '' if lang == 'batch' else '#'
        toks = list(lex)
    except ValueError:
        toks = line.split()
    if not posix:
        toks = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in '"\'' else t for t in toks]
    return toks


class Checker:
    """Reads script files and collects findings for each."""

    def __init__(self, tables=None):
        self.tables = tables or Tables()
        self.gam = GamParser(self.tables)

    def check_file(self, path, depth=0, lang=None):
        """Return the findings for one file."""
        path = Path(path)
        data = path.read_bytes()
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = data.decode('utf-16', errors='replace')
        else:
            text = data.decode('utf-8-sig', errors='replace')
        lang = lang or self.language(path, text)
        return self.check_text(text, str(path), lang, [path.resolve().parent, Path.cwd()], depth)

    def check_text(self, text, name, lang, base_dirs=None, depth=0):
        """Return the findings for script text that did not come from a file, such as a paste."""
        ctx = Context(name, base_dirs or [Path.cwd()], self, depth)
        if lang == 'python':
            findings = self._python(text, ctx)
        else:
            findings = self._shell_like(text, lang, ctx)
        return sorted(findings, key=lambda f: (f.file != ctx.file, f.line))

    @staticmethod
    def language(path, text):
        """Pick a reader from the extension, then the shebang."""
        ext = path.suffix.lower()
        by_ext = {'.py': 'python', '.ps1': 'powershell', '.psm1': 'powershell', '.bat': 'batch', '.cmd': 'batch',
                  '.txt': 'gambatch', '.gam': 'gambatch'}
        if ext in by_ext:
            return by_ext[ext]
        first = text.split('\n', 1)[0]
        if first.startswith('#!') and 'python' in first:
            return 'python'
        if first.startswith('#!') and 'pwsh' in first:
            return 'powershell'
        # No extension or shebang (a paste): the line-continuation character
        # and variable syntax are the only clues to which shell it was written for.
        if re.search(r'`\s*$|\$env:|\$_\b', text, re.M):
            return 'powershell'
        if re.search(r'\^\s*$|%[A-Za-z_]\w*%|%~?\d', text, re.M):
            return 'batch'
        return 'shell'

    # ----- shell, PowerShell, batch, gam batch files

    def _shell_like(self, text, lang, ctx):
        lines = _logical_lines(text, lang)
        gam_vars, wrappers = self._shell_aliases(lines, lang)
        findings, code_lines = [], []
        for n, line in lines:
            body = line.strip()
            if not body or (lang == 'batch' and re.match(r'(?i)^(rem\b|::)', body)):
                continue
            toks = _tokenise(body, lang)
            code_lines.append((n, toks))
            if lang == 'gambatch' and toks and toks[0].lower() == 'execute':
                findings.extend(self._local(' '.join(toks[1:]), ctx, n, UNKNOWN,
                                            'runs an operating system command from a tbatch file'))
                continue
            segments, seps, cur = [], [], []
            for t in toks:
                # shlex glues a run of punctuation into one token: ');' after $(...) is two separators
                if t in SEPARATORS or (t and set(t) <= set(';&|()')):
                    segments.append(cur)
                    seps.append(t)
                    cur = []
                else:
                    cur.append(t)
            segments.append(cur)
            seps.append('')
            local_text = []
            for seg, sep in zip(segments, seps):
                seg = self._drop_redirects(seg)
                at = self._gam_position(seg, gam_vars, wrappers)
                if at is None:
                    if seg and seg[0].lower().strip('`"\'') in ECHO_WORDS and lang in ('shell', 'gambatch', 'powershell'):
                        # echo "$(gam delete ...)" prints text but the shell runs the substitution first
                        for inner in self._substitutions(body, lang):
                            if inner in ' '.join(seg):
                                for f in self.check_text(inner, ctx.file, lang, ctx.base_dirs, ctx.depth + 1):
                                    f.line = n
                                    f.note = '; '.join(x for x in (f.note, 'run by a command substitution inside echo/printf') if x)
                                    findings.append(f)
                    if self._gam_hidden(seg, gam_vars, wrappers):
                        findings.append(Finding(ctx.file, n, UNKNOWN, 'gam appears in a command the checker could not follow',
                                                short(seg), note='handed to another program (bash -c, ssh, Start-Process); check the inner command on its own'))
                    elif (script := self._script_path(seg)) is not None:
                        findings.extend(ctx.follow_script(script, n, short(seg)))
                    local_text.extend([' '.join(seg), sep])
                    continue
                args = [_dynamic(t, lang) for t in seg[at + 1:]]
                if args and all(isinstance(t, Dyn) for t in args) and any(t.startswith(('$@', '"$@', '$*', '@args', '%*')) for t in args):
                    continue  # the body of a wrapper function; its callers are checked instead
                findings.extend(self.gam.parse(args, ctx, n))
            findings.extend(self._local(' '.join(t for t in local_text if t), ctx, n))
        findings.extend(self._credentials(code_lines, ctx))
        if not any(f.command.startswith('gam') for f in findings) and ctx.depth == 0:
            findings.append(Finding(ctx.file, 0, UNKNOWN, f'no gam commands found in {len(lines)} lines',
                                    note='if this script does run gam, the checker could not see how'))
        return findings

    @staticmethod
    def _substitutions(line, lang):
        """Text inside each $(...) and `...` on a line that the shell would run: not single-quoted, not escaped.

        shortcut: parentheses are counted without reading quotes inside a substitution; upgrade if one hides a real case.
        """
        out, i, quote = [], 0, ''
        while i < len(line):
            c = line[i]
            if c == '\\' and quote != "'" and lang != 'powershell':
                i += 2
                continue
            if c in '\'"' and quote in ('', c):
                quote = '' if quote else c
            elif quote != "'" and line.startswith('$(', i):
                depth, j = 1, i + 2
                while j < len(line) and depth:
                    depth += (line[j] == '(') - (line[j] == ')')
                    j += 1
                out.append(line[i + 2:j - 1 if depth == 0 else j])
                i = j
                continue
            elif c == '`' and quote != "'" and lang != 'powershell':
                j = line.find('`', i + 1)
                j = len(line) if j < 0 else j
                out.append(line[i + 1:j])
                i = j
            i += 1
        return out

    @staticmethod
    def _gam_hidden(seg, gam_vars, wrappers):
        """True when a segment that is not a gam command still carries one: bash -c "gam ...", "$(gam ...)", ssh host 'gam ...'.
        Echoed text and assignments (GAM=/path/gam, $gam = "...") are not hidden commands."""
        if not seg or seg[0].lower().strip('`"\'') in ECHO_WORDS or (len(seg) > 1 and seg[1] in ('=', '+=')):
            return False
        if any(GAM_INSIDE.search(t) for t in seg):
            return True  # result="$(gam delete ...)" is a command; GAM=/path/gam is not
        head = next((t for t in seg if not re.fullmatch(r'[A-Za-z_]\w*=.*', t)), '')
        if head.lower().strip('`"\'') in FILE_COMMANDS:
            return False
        for t in seg:
            if not re.fullmatch(r'[A-Za-z_]\w*=.*', t) and _gam_name(t.strip('`"\''), gam_vars, wrappers):
                return True
        return False

    @staticmethod
    def _script_path(seg):
        """The script a segment runs: python3 x.py, bash x.sh, pwsh -File x.ps1, ./x.sh, sudo bash x.sh.

        python -m, python -c and bash -c run code that is not a file, so they return None.
        """
        k = 0
        while k < len(seg) and (re.fullmatch(r'[A-Za-z_]\w*=.*', seg[k]) or
                                (seg[k].lower() in PREFIX_WORDS and seg[k].lower() not in SCRIPT_RUNNERS)):
            k += 1
        if k >= len(seg):
            return None
        word = seg[k].strip('`"\'')
        if word.lower().endswith(SCRIPT_EXTS):
            return word
        if re.split(r'[\\/]', word)[-1].lower().removesuffix('.exe') not in SCRIPT_RUNNERS:
            return None
        args = [t.strip('`"\'') for t in seg[k + 1:]]
        if any(t.lower() in ('-m', '-c', '-command', '-encodedcommand') for t in args):
            return None
        names = [t for t in args if not t.startswith('-')]
        return next((t for t in names if t.lower().endswith(SCRIPT_EXTS)), names[0] if names else None)

    @staticmethod
    def _drop_redirects(seg):
        out, skip = [], False
        for t in seg:
            if skip:
                skip = False
                continue
            if t in REDIRECTS or re.fullmatch(r'\d?>{1,2}&?\d?|\d?<', t):
                skip = not re.fullmatch(r'\d?>&\d', t)
                continue
            out.append(t)
        return out

    @staticmethod
    def _gam_position(seg, gam_vars, wrappers):
        """Index of the gam executable when it is the command being run, not text passed to echo or grep."""
        k = 0
        while k < len(seg):
            t = seg[k].strip('`')
            if re.fullmatch(r'[A-Za-z_]\w*=.*', t):
                k += 1  # VAR=value prefix or plain assignment, even when the value is a gam path
                continue
            if _gam_name(t, gam_vars, wrappers):
                # $gam = "C:\GAM7\gam.exe" assigns the path; it does not run gam
                return None if k + 1 < len(seg) and seg[k + 1] in ('=', '+=') else k
            w = t.lower()
            if w in ECHO_WORDS:
                return None
            if w in PREFIX_WORDS:
                # the wrapper's own options (sudo -u x, timeout 300, nice -n 10) sit between it and gam
                for j in range(k + 1, len(seg)):
                    if _gam_name(seg[j].strip('`'), gam_vars, wrappers):
                        return None if j + 1 < len(seg) and seg[j + 1] in ('=', '+=') else j
                k += 1
                continue
            return None
        return None

    @staticmethod
    def _shell_aliases(lines, lang):
        """Find variables holding gam's path and wrapper functions that pass their arguments to gam."""
        gam_vars, wrappers = set(), set()
        assign = {
            'shell': r'^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(.+)$',
            'gambatch': r'^\s*(?:export\s+)?([A-Za-z_]\w*)=(.+)$',
            'powershell': r'^\s*\$(?:env:)?([A-Za-z_]\w*)\s*=\s*(.+)$',
            'batch': r'(?i)^\s*set\s+"?([A-Za-z_]\w*)=\s*"?([^"]*)"?\s*$',
        }[lang]
        for _, line in lines:
            m = re.match(assign, line)
            if m and _gam_name(m.group(2).strip().strip('"\'').split()[0] if m.group(2).strip() else '', set(), set()):
                gam_vars.add(m.group(1).lower())
            m = re.match(r'^\s*alias\s+([\w-]+)=[\'"]?(\S+)', line)
            if m and _gam_name(m.group(2).strip('"\''), set(), set()):
                wrappers.add(m.group(1))
            m = re.match(r'(?i)^\s*Set-Alias\s+(?:-Name\s+)?([\w-]+)\s+(?:-Value\s+)?(\S+)', line)
            if m and _gam_name(m.group(2).strip('"\''), set(), set()):
                wrappers.add(m.group(1))
        text = '\n'.join(line for _, line in lines)
        for m in re.finditer(r'(?im)^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*(?:\(\s*\))?\s*\{([^}]*)\}', text):
            name, body = m.group(1), m.group(2)
            if name.lower() == 'function':
                continue
            has_gam = any(_gam_name(t.strip('&"\'`'), gam_vars, set()) for t in re.split(r'[\s;]+', body))
            if has_gam and re.search(r'\$@|\$\*|@args|\$args', body):
                wrappers.add(name)
        return gam_vars, wrappers

    def _local(self, text, ctx, line, fallback=None, fallback_what=''):
        """Apply the local-damage rules to non-gam text; the first rule per level wins."""
        found, seen = [], set()
        for level, pattern, what in LOCAL_RULES:
            if level in seen:
                continue
            if re.search(pattern, text):
                if level == CHANGES and DESTRUCTIVE in seen:
                    continue
                seen.add(level)
                found.append(Finding(ctx.file, line, level, what, short([text.strip()]), note='on this computer'))
        if not found and fallback is not None and text.strip():
            found.append(Finding(ctx.file, line, fallback, fallback_what, short([text.strip()])))
        return found

    @staticmethod
    def _credentials(code_lines, ctx):
        """A script that touches GAM's credential files and can reach the network may be stealing the tenant.

        code_lines are (line, tokens) with comments already removed, so a
        comment explaining where oauth2.txt lives does not count.
        """
        cred = next(((n, m.group(0)) for n, toks in code_lines for t in toks if (m := CREDENTIAL_RE.search(t))), None)
        if not cred:
            return []
        net = any(t.lower().strip('&"\'') in NETWORK_COMMANDS for _, toks in code_lines for t in toks)
        if net:
            return [Finding(ctx.file, cred[0], SUSPICIOUS, "reads GAM's credential files and can send data over the network",
                            cred[1], security='whoever holds these files controls the tenant')]
        return [Finding(ctx.file, cred[0], UNKNOWN, "refers to GAM's credential files", cred[1],
                        note='gam scripts do not normally need to open these')]

    # ----- Python

    def _python(self, text, ctx):
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            return [Finding(ctx.file, e.lineno or 0, UNKNOWN, f'Python could not be parsed: {e.msg}')]
        py = _PythonReader(tree, self, ctx)
        findings = py.run()
        if not any(f.command.startswith('gam') for f in findings) and ctx.depth == 0:
            findings.append(Finding(ctx.file, 0, UNKNOWN, 'no gam commands found',
                                    note='if this script does run gam, the checker could not see how'))
        return findings


EXEC_CALLS = {'subprocess.run', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output',
              'subprocess.Popen', 'subprocess.getoutput', 'subprocess.getstatusoutput', 'os.system', 'os.popen',
              'os.execvp', 'os.execv', 'os.spawnvp', 'asyncio.create_subprocess_exec',
              'asyncio.create_subprocess_shell'}
PY_LOCAL = {
    'shutil.rmtree': (DESTRUCTIVE, 'deletes a local folder tree'),
    'os.remove': (CHANGES, 'deletes a local file'), 'os.unlink': (CHANGES, 'deletes a local file'),
    'os.rmdir': (CHANGES, 'deletes a local folder'), 'os.removedirs': (CHANGES, 'deletes local folders'),
    'eval': (SUSPICIOUS, 'runs text as Python code'), 'exec': (SUSPICIOUS, 'runs text as Python code'),
    'compile': (UNKNOWN, 'compiles Python code built at runtime'),
}
PLACEHOLDER = '\x00'


class _Splat:
    """Marks where a wrapper function's parameters land in the gam argument list."""

    def __init__(self, name, mode):
        self.name, self.mode = name, mode


class _PythonReader:
    """Find gam invocations in Python: subprocess calls, wrapper functions, and gam command strings."""

    def __init__(self, tree, checker, ctx):
        self.tree, self.checker, self.ctx = tree, checker, ctx
        self.aliases = {}
        self.consumed = set()
        self.wrappers = {}
        self.findings = []
        self.parent = {}
        self.scopes = {}   # function node (or None for module level) -> {name: [assigned values]}
        self.local = {}

    def run(self):
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    self.aliases[n.asname or n.name] = n.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for n in node.names:
                    self.aliases[n.asname or n.name] = f'{node.module}.{n.name}'
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    scope = self.scopes.setdefault(self._enclosing(node), {})
                    scope.setdefault(targets[0].id, []).append(node.value)
                elif len(targets) == 1 and isinstance(targets[0], ast.Subscript) and isinstance(targets[0].value, ast.Name):
                    # cmd[1] = 'delete' after cmd = [...]: a second value makes the name a runtime value
                    self.scopes.setdefault(self._enclosing(node), {}).setdefault(targets[0].value.id, []).append(node)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                self.scopes.setdefault(self._enclosing(node), {}).setdefault(node.target.id, []).append(node)  # cmd += [...]
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                    and node.func.attr in ('append', 'extend', 'insert', 'pop', 'remove', 'clear', 'reverse', 'sort'):
                self.scopes.setdefault(self._enclosing(node), {}).setdefault(node.func.value.id, []).append(node)  # cmd.append(...): runtime
        functions = [fn for fn in ast.walk(self.tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for fn in functions:
            self.local = self.scopes.get(fn, {})
            self._find_wrapper(fn)
        # A function that hands work to a wrapper (pool.submit(run_gam, args)) is
        # itself a wrapper, but the shape it takes commands in is its own.
        self.indirect = {}
        for _ in range(3):
            for fn in functions:
                known = set(self.wrappers) | set(self.indirect)
                if fn.name in known:
                    continue
                # Only a wrapper passed as a value counts; a direct call to it is already checked where it happens.
                refs = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)
                        and not (isinstance(self.parent.get(n), ast.Call) and self.parent[n].func is n)} & known
                if refs:
                    ref = sorted(refs)[0]
                    self.indirect[fn.name] = self.wrappers[ref][0] if ref in self.wrappers else self.indirect[ref]
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self.local = self.scopes.get(self._enclosing(node), {})
                self._call(node)
        self._strings()
        self.findings.extend(self._credentials())
        return self.findings

    def _enclosing(self, node):
        """The function a node sits in, or None at module level."""
        node = self.parent.get(node)
        while node is not None and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            node = self.parent.get(node)
        return node

    def _name(self, func):
        """Dotted name of a called function with import aliases resolved."""
        if isinstance(func, ast.Name):
            return self.aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            base = self._name(func.value)
            return f'{base}.{func.attr}' if base else func.attr
        return None

    def _const(self, name):
        """The value of a name assigned exactly once in the current function, else at module level.

        A name assigned twice is a runtime value; guessing which assignment
        applies would be exactly the silent wrong answer this tool exists to avoid.
        """
        for scope in (self.local, self.scopes.get(None, {})):
            if name in scope:
                values = scope[name]
                return values[0] if len(values) == 1 else None
        return None

    def _string(self, node, params=()):
        """Resolve a string expression, putting PLACEHOLDER where a runtime value goes."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            self.consumed.add(id(node))
            return node.value
        if isinstance(node, ast.JoinedStr):
            self.consumed.add(id(node))
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    inner = self._string(v.value, params)
                    parts.append(inner if inner is not None and PLACEHOLDER not in inner else PLACEHOLDER)
            return ''.join(parts)
        if isinstance(node, ast.Name):
            if node.id in params:
                return PLACEHOLDER
            const = self._const(node.id)
            return self._string(const, params) if const is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._string(node.left, params), self._string(node.right, params)
            return left + right if left is not None and right is not None else None
        if isinstance(node, ast.Call):
            name = self._name(node.func) or ''
            if name.endswith('.format') and isinstance(node.func, ast.Attribute):
                base = self._string(node.func.value, params)
                return re.sub(r'\{[^}]*\}', PLACEHOLDER, base) if base is not None else None
            if name in ('os.path.expanduser', 'os.path.expandvars', 'str', 'pathlib.Path', 'Path', 'shutil.which') and node.args:
                return self._string(node.args[0], params)
            if name in ('os.path.join',) and node.args:
                parts = [self._string(x, params) for x in node.args]
                return '/'.join(parts) if all(p is not None for p in parts) else None
        return None

    def _argv(self, node, params=()):
        """Resolve an argument list into tokens, Dyn for runtime values, _Splat for wrapper parameters."""
        if isinstance(node, (ast.List, ast.Tuple)):
            self.consumed.add(id(node))
            out = []
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    if isinstance(elt.value, ast.Name) and elt.value.id in params:
                        out.append(_Splat(elt.value.id, 'splat'))
                    else:
                        sub = self._argv(elt.value, params)
                        out.extend(sub if sub is not None else [Dyn('*' + ast.unparse(elt.value))])
                    continue
                s = self._string(elt, params)
                out.append(Dyn(ast.unparse(elt)) if s is None or PLACEHOLDER in s else s)
            return out
        if isinstance(node, ast.Name):
            if node.id in params:
                return [_Splat(node.id, 'list')]
            const = self._const(node.id)
            if const is not None:
                return self._argv(const, params)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._argv(node.left, params), self._argv(node.right, params)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.Call):
            name = self._name(node.func) or ''
            if name in ('list', 'tuple') and node.args:
                return self._argv(node.args[0], params)
            if name == 'shlex.split' and node.args:
                return self._split(self._string(node.args[0], params))
            if name.endswith('.split') and isinstance(node.func, ast.Attribute) and not node.args:
                return self._split(self._string(node.func.value, params))
        s = self._string(node, params)
        if s is not None:
            return self._split(s)
        return None

    @staticmethod
    def _split(s):
        if s is None:
            return None
        try:
            parts = shlex.split(s, posix=True)
        except ValueError:
            parts = s.split()
        return [Dyn(p.replace(PLACEHOLDER, '{...}')) if PLACEHOLDER in p else p for p in parts]

    def _exec_argv(self, call, params=()):
        """For a subprocess/os call, return (tokens, via_shell) or (None, ...) when unreadable."""
        target = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg in ('args', 'command', 'cmd')), None)
        if target is None:
            return None, False
        return self._argv(target, params), any(k.arg == 'shell' for k in call.keywords)

    def _is_gam(self, tok):
        if isinstance(tok, _Splat):
            return False
        if isinstance(tok, Dyn):
            return 'gam' in tok.lower()
        return _gam_name(tok, set(), set())

    def _find_wrapper(self, fn):
        """A function that passes its own arguments to gam is a wrapper; its call sites are the real commands."""
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
        if fn.args.vararg:
            params.add(fn.args.vararg.arg)
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and self._name(node.func) in EXEC_CALLS:
                toks, _ = self._exec_argv(node, params)
                if not toks or not self._is_gam(toks[0]):
                    continue
                splats = [k for k, t in enumerate(toks) if isinstance(t, _Splat)]
                if splats:
                    k = splats[0]
                    self.wrappers[fn.name] = (toks[1:k], toks[k], [a.arg for a in fn.args.args], node)
                    return

    def _call(self, node):
        name = self._name(node.func) or ''
        short_name = name.rsplit('.', 1)[-1]
        if name in PY_LOCAL or (name.endswith('.unlink') and not name.startswith('os.')):
            level, what = PY_LOCAL.get(name, (CHANGES, 'deletes a local file'))
            if name in ('eval', 'exec', 'compile') and node.args and isinstance(node.args[0], ast.Constant):
                self._constant_code(node, name)
                return
            self.findings.append(Finding(self.ctx.file, node.lineno, level, what, ast.unparse(node)[:140],
                                         note='on this computer'))
            return
        if short_name in self.wrappers and name not in EXEC_CALLS:
            self._wrapper_call(node, short_name)
            return
        if short_name in self.indirect and name not in EXEC_CALLS:
            self._indirect_call(node, short_name)
            return
        if name not in EXEC_CALLS:
            return
        if any(node is w[3] for w in self.wrappers.values()):
            return
        toks, via_shell = self._exec_argv(node)
        via_shell = via_shell or name in ('os.system', 'os.popen', 'subprocess.getoutput', 'subprocess.getstatusoutput',
                                          'asyncio.create_subprocess_shell')
        line = node.lineno
        if toks is None:
            src = ast.unparse(node)
            level = UNKNOWN
            self.findings.append(Finding(self.ctx.file, line, level, 'runs a command built at runtime', src[:140],
                                         note='could be gam or anything else'))
            return
        if toks and self._is_gam(toks[0]) and not via_shell:
            self.findings.extend(self.checker.gam.parse(toks[1:], self.ctx, line))
            return
        # runtime values keep a $ so the shell reader marks them as decided at runtime
        text = ' '.join((t if t.startswith('$') else '$' + t) if isinstance(t, Dyn) else str(t) for t in toks)
        found = self.checker.check_text(text, self.ctx.file, 'shell', self.ctx.base_dirs, depth=1)
        for f in found:
            f.line = line
        if not found and any(isinstance(t, Dyn) for t in toks[:1]):
            found = [Finding(self.ctx.file, line, UNKNOWN, 'runs a program chosen at runtime', short(toks))]
        self.findings.extend(found)

    def _constant_code(self, node, name):
        """exec/compile of a literal string: parse it as Python (never run it) and read it like the rest of the file.

        eval is not read, and text that does not parse is not guessed at; both are CANNOT TELL.
        """
        src = node.args[0].value
        tree = None
        if name != 'eval' and isinstance(src, (str, bytes)):
            try:
                tree = ast.parse(src)
            except (SyntaxError, ValueError):
                pass
        if tree is None:
            self.findings.append(Finding(self.ctx.file, node.lineno, UNKNOWN, f'runs Python text the checker could not read ({name})',
                                         ast.unparse(node)[:140], note='could be gam or anything else'))
            return
        for f in _PythonReader(tree, self.checker, self.ctx).run():
            f.line = node.lineno
            f.note = '; '.join(n for n in (f.note, f'inside {name}()') if n)
            self.findings.append(f)

    def _wrapper_call(self, node, name):
        prefix, splat, arg_names, _ = self.wrappers[name]
        line = node.lineno
        if splat.mode == 'splat':
            # def gam(*args): run([GAM, *args]) -> gam("user", x, "delete") ; skip positional params before *args
            fixed = len(arg_names) - (1 if arg_names and arg_names[0] == 'self' else 0)
            values = node.args[fixed:] if splat.name not in arg_names else node.args
            toks = []
            for v in values:
                if isinstance(v, ast.Starred):
                    sub = self._argv(v.value)
                    toks.extend(sub if sub is not None else [Dyn('*' + ast.unparse(v.value))])
                else:
                    s = self._string(v)
                    toks.append(Dyn(ast.unparse(v)) if s is None or PLACEHOLDER in s else s)
        else:
            idx = arg_names.index(splat.name) if splat.name in arg_names else 0
            if arg_names and arg_names[0] == 'self' and isinstance(node.func, ast.Attribute):
                idx -= 1
            target = node.args[idx] if idx < len(node.args) else None
            toks = self._argv(target) if target is not None else None
            if toks is None:
                toks = [Dyn(ast.unparse(target) if target is not None else '?')]
        self.findings.extend(self.checker.gam.parse(list(prefix) + toks, self.ctx, line))

    def _indirect_call(self, node, name):
        """Check every flat list literal passed to an indirect wrapper as a gam argument list."""
        prefix = self.indirect[name]
        values = list(node.args) + [k.value for k in node.keywords]
        lists = [n for v in values for n in ast.walk(v)
                 if isinstance(n, ast.List) and n.elts and not any(isinstance(e, (ast.List, ast.Dict, ast.Tuple)) for e in n.elts)]
        if not lists:
            self.findings.append(Finding(self.ctx.file, node.lineno, UNKNOWN, f'passes gam commands through {name}()',
                                         ast.unparse(node)[:140], note='the commands could not be read'))
            return
        for lst in lists:
            toks = self._argv(lst) or [Dyn(ast.unparse(lst))]
            self.findings.extend(self.checker.gam.parse(list(prefix) + toks, self.ctx, lst.lineno))

    def _strings(self):
        """gam command text that was not traced to a call, e.g. a list of commands run in a loop."""
        for node in ast.walk(self.tree):
            if isinstance(self.parent.get(node), ast.JoinedStr):
                continue  # a fragment of an f-string; the whole f-string is checked instead
            if isinstance(node, (ast.Constant, ast.JoinedStr)) and id(node) not in self.consumed:
                self.local = self.scopes.get(self._enclosing(node), {})
                s = self._string(node)
                if s and re.match(r'^\s*(?:\S*[/\\])?gam(?:\.exe)?\s+[A-Za-z]', s):
                    toks = self._split(s)
                    for f in self.checker.gam.parse(toks[1:], self.ctx, node.lineno):
                        f.note = '; '.join(n for n in (f.note, 'found as text; how it is run was not traced') if n)
                        self.findings.append(f)
        self._argument_lists()

    def _argument_lists(self):
        """gam argument lists kept as data and run later, e.g. Module(args=["print", "users"]).

        Only in a script that names gam somewhere, and only lists GAM7 fully
        recognises, because ordinary lists like choices=["print", "info"] would
        otherwise read as broken gam commands.
        """
        names_gam = any(
            (isinstance(n, ast.Constant) and isinstance(n.value, str) and _gam_name(n.value.strip(), set(), set()))
            or (isinstance(n, ast.Name) and 'gam' in n.id.lower())
            for n in ast.walk(self.tree))
        if not names_gam:
            return
        gp = self.checker.gam
        starts = (set(gp.tb.t['MAIN_COMMANDS_WITH_OBJECTS']) | set(gp.tb.t['BATCH_CSV_COMMANDS'])
                  | gp.tb.user_types | gp.tb.cros_types | gp.tb.selectors)
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.List) or id(node) in self.consumed or len(node.elts) < 2:
                continue
            first = node.elts[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.lower() in starts):
                continue
            self.local = self.scopes.get(self._enclosing(node), {})
            toks = self._argv(node)
            if not toks or any(isinstance(t, _Splat) for t in toks):
                continue
            for f in gp.parse(toks, self.ctx, node.lineno):
                if f.what.startswith(('not a command', 'incomplete', 'the gam command itself')):
                    continue
                f.note = '; '.join(n for n in (f.note, 'gam arguments kept as data; how they are run was not traced') if n)
                self.findings.append(f)

    def _credentials(self):
        """Credential filenames in code (not comments or docstrings), judged with the modules imported."""
        net_modules = {'requests', 'urllib', 'http', 'httpx', 'aiohttp', 'smtplib', 'ftplib', 'paramiko', 'socket',
                       'pycurl', 'boto3'}
        imported = {v.split('.')[0] for v in self.aliases.values()}
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if isinstance(self.parent.get(node), ast.Expr):
                continue  # docstring or bare string statement
            m = CREDENTIAL_RE.search(node.value)
            if not m:
                continue
            if imported & net_modules:
                return [Finding(self.ctx.file, node.lineno, SUSPICIOUS,
                                "reads GAM's credential files and imports network modules",
                                m.group(0), security='whoever holds these files controls the tenant')]
            return [Finding(self.ctx.file, node.lineno, UNKNOWN, "refers to GAM's credential files", m.group(0),
                            note='gam scripts do not normally need to open these')]
        return []


# ----- report


def verdict(findings):
    """The worst level among the findings."""
    return max((f.level for f in findings), default=UNKNOWN)


DOTS = ['\U0001F7E2', '\U0001F7E0', '⚪', '\U0001F534', '\U0001F534']  # green, orange, white, red, red; by level


def tenant_unguarded(findings, path):
    """Line of the first change in the checked file when no gam info domain comes before it, else None.

    A script run under the wrong gam.cfg section changes the wrong tenant; reading
    gam info domain first and stopping on a customer-ID mismatch is the guard."""
    own = sorted((f for f in findings if f.file == path), key=lambda f: f.line)
    for f in own:
        if re.search(r'\binfo\s+domain\b', f.command, re.I):
            return None
        if f.level in (CHANGES, DESTRUCTIVE):
            return f.line
    return None


def can_print_dots(stream):
    """True when the stream can encode the level dots.

    A Windows console on a legacy code page cannot print emoji, and
    errors='replace' would turn each dot into '?', so those consoles keep the
    plain ASCII report.
    """
    try:
        ''.join(DOTS).encode(stream.encoding or 'ascii')
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def render(path, findings, tables, quiet=False, dots=False):
    """Plain-text report. ASCII unless dots=True, which prefixes each level with a coloured dot."""
    v = verdict(findings)
    dot = (lambda lvl: DOTS[lvl] + ' ') if dots else (lambda lvl: '')
    pad = '   ' if dots else ''  # a dot is two columns wide plus its space
    counts = {name: sum(1 for f in findings if f.level == lvl) for lvl, name in enumerate(LEVEL_NAMES)}
    sec = sum(1 for f in findings if f.security)
    out = [f'gamcheck {__version__}: {path}', f'Checked against GAM7 {tables.version}', '',
           f'VERDICT: {dot(v)}{LEVEL_NAMES[v]}',
           '  ' + ', '.join(f'{n} {k.lower()}' for k, n in counts.items() if n)
           + (f'; {sec} security-sensitive' if sec else ''), '']
    unguarded = tenant_unguarded(findings, str(path))
    if unguarded:
        out += [f'NOTE: nothing checks which tenant GAM is pointed at before the first change (L{unguarded}).',
                '      A gam info domain check that stops on the wrong customer ID belongs above it.', '']
    older = sorted({f.note.split(';')[0][len('written for '):] for f in findings if f.note.startswith('written for ')})
    if older:
        out += [f'NOTE: parts of this script are written for {", ".join(older)} and will fail on GAM7.', '']
    for f in sorted(findings, key=lambda x: (x.file, x.line)):
        if quiet and f.level == READ:
            continue
        where = f'L{f.line}' if f.file == str(path) else f'{Path(f.file).name}:L{f.line}'
        out.append(f'  {where:<8} {dot(f.level)}{LEVEL_NAMES[f.level]:<12} {f.what}')
        if f.security:
            out.append(f'  {"":<8} {pad}{"SECURITY":<12} {f.security}')
        if f.note:
            out.append(f'  {"":<8} {pad}{"":<12} ({f.note})')
        if f.undo:
            out.append(f'  {"":<8} {pad}{"UNDO":<12} {f.undo}')
        if f.command:
            out.append(f'  {"":<8} {pad}{"":<12} > {f.command}')
        if f.docs and f.level > READ:
            out.append(f'  {"":<8} {pad}{"":<12} docs: {f.docs}')
    out += ['', 'This is a reading of the script text, not a guarantee. It says what a command would DO,',
            'never whether GAM will accept it. Values chosen at runtime show as CANNOT TELL.']
    return '\n'.join(out)


# Forum posts copy the shell prompt along with the command ("$ gam ...",
# "> gam ...", "PS C:\> gam ...", "C:\GAM7> gam ..."). Left in, the line
# does not start with gam and the paste reads as "no gam commands found".
PROMPT_PREFIX = re.compile(r'^[ \t]*(?:\$|>|%|PS [^>\n]*>|[A-Za-z]:\\[^>\n]*>)[ \t]*(?=(?:\S*[/\\])?gam)', re.M | re.I)
STRAIGHTEN = str.maketrans({'“': '"', '”': '"', '„': '"', '‘': "'", '’': "'"})


def read_paste():
    """Read pasted commands from the terminal until an empty line, or all of a pipe.

    A blank line ends a paste because the end-of-input key differs between
    Mac/Linux (Ctrl+D) and Windows (Ctrl+Z, Enter). A pasted script with blank
    lines in it is therefore cut short; the prompt says to use a file for those.
    """
    if not sys.stdin.isatty():
        # Windows decodes a pipe with the console code page, which turns UTF-8
        # curly quotes into mojibake that STRAIGHTEN no longer matches.
        data = sys.stdin.buffer.read()
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            return data.decode('utf-16', errors='replace')
        try:
            return data.decode('utf-8-sig')
        except UnicodeDecodeError:
            return data.decode(sys.stdin.encoding or 'utf-8', errors='replace')
    try:
        # Without readline, macOS reads a terminal line through the kernel's
        # canonical mode, which truncates a line at 1024 bytes.
        import readline  # noqa: F401
    except ImportError:
        pass
    print('Paste the gam command(s), then press Enter on an empty line.\n'
          '(For a whole script with blank lines in it, run: gamcheck yourscript.sh)', file=sys.stderr)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            if lines:
                break
            continue
        lines.append(line)
    return '\n'.join(lines) + '\n'


def main(argv=None):
    """Check each script named on the command line; exit with the worst verdict."""
    if sys.version_info < (3, 9):
        print('gamcheck needs Python 3.9 or newer', file=sys.stderr)
        return UNKNOWN
    # Script text echoed in the report can hold characters a Windows console
    # code page cannot print; replace them rather than crash mid-report.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    ap = argparse.ArgumentParser(description='Report what a GAM script would do, without running it.')
    ap.add_argument('scripts', nargs='*',
                    help='script files to check; none, or --paste, asks you to paste commands; - reads a pipe')
    ap.add_argument('--paste', action='store_true', help='ask for gam commands to paste in')
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    ap.add_argument('--quiet', action='store_true', help='hide read-only lines')
    opts = ap.parse_args(argv)
    checker = Checker()
    worst, reports = READ, []
    if opts.paste or not opts.scripts:
        opts.scripts = ['-'] + [s for s in opts.scripts if s != '-']
    for s in opts.scripts:
        if s == '-':
            text = read_paste()
            if not text.strip():
                print('gamcheck: nothing was pasted', file=sys.stderr)
                worst = max(worst, UNKNOWN)
                continue
            s = '<pasted>'
            # Check the text as the author meant it, but still tell the user the
            # curly quotes are there, because they will paste the same text into gam.
            curly = text.translate(STRAIGHTEN) != text
            straight = PROMPT_PREFIX.sub('', text.translate(STRAIGHTEN))
            lang = Checker.language(Path(''), straight)
            findings = checker.check_text(straight, s, lang)
            print(f'Read {len(text.splitlines())} line(s) as {lang}.', file=sys.stderr)
            if curly:
                findings.append(Finding(s, 0, UNKNOWN, 'the paste contains curly quotes',
                                        note='web pages turn " into curly quotes; gam will reject them, retype them as straight quotes'))
        elif not Path(s).is_file():
            print(f'gamcheck: {s}: file not found', file=sys.stderr)
            worst = max(worst, UNKNOWN)
            continue
        else:
            try:
                findings = checker.check_file(Path(s))
            except Exception as e:  # a checker bug must read as CANNOT TELL, never as a mild exit code
                findings = [Finding(s, 0, UNKNOWN, f'gamcheck could not read this script ({type(e).__name__}: {e})',
                                    note='report this at the repository; the verdict is not a reading of the script')]
        worst = max(worst, verdict(findings))
        if opts.json:
            reports.append({'file': s, 'gam_version': checker.tables.version, 'verdict': LEVEL_NAMES[verdict(findings)],
                            'findings': [f.as_dict() for f in findings]})
        else:
            print(render(s, findings, checker.tables, opts.quiet, can_print_dots(sys.stdout)))
            print()
    if opts.json:
        print(json.dumps(reports, indent=2))
    return worst


if __name__ == '__main__':
    sys.exit(main())
