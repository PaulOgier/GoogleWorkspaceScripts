/*
 * Exercise offboarding_command_builder.html for real: load the page, tick
 * boxes, read the command it produces. A flag can be declared in the HTML and
 * never reach the output, which no amount of grepping the file will catch.
 *
 * Needs jsdom, which this repo does not otherwise depend on:
 *     npm install jsdom
 *     node test_command_builder.js
 *
 * Exits non-zero on the first failed assertion.
 */
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'offboarding_command_builder.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'http://localhost/' });
const { window } = dom;
const d = window.document;
const $ = id => d.getElementById(id);
const fire = (el, ev = 'change') => el.dispatchEvent(new window.Event(ev, { bubbles: true }));
const out = () => d.querySelector('textarea').value;

let fails = 0;
function check(name, cond, extra = '') {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + name + (cond ? '' : '  <<< ' + extra));
  if (!cond) fails++;
}

$('user').value = 'leaver@example.com';
fire($('user'), 'input');

const scorched = d.querySelector('input[name="mode"][value="scorched"]');
scorched.checked = true; fire(scorched);
$('scorched-confirm').value = 'leaver@example.com';
fire($('scorched-confirm'), 'input');

check('--allow-orphaned-shared-drives checkbox exists', !!$('allow-orphaned-shared-drives'));
check('it lives in the scorched-earth panel',
      !!$('scorched-panel') && $('scorched-panel').contains($('allow-orphaned-shared-drives')));
check('unticked: absent from the command',
      !out().includes('--allow-orphaned-shared-drives'), out());

$('allow-orphaned-shared-drives').checked = true;
fire($('allow-orphaned-shared-drives'));
const s = out();
check('ticked: present', s.includes('--allow-orphaned-shared-drives'), s);
check('ticked: still a scorched-earth command',
      s.includes('--scorched-earth') && s.includes('--doit') && s.includes('--force'), s);
check('emitted exactly once',
      (s.match(/--allow-orphaned-shared-drives/g) || []).length === 1, s);

// Outside scorched-earth the flag does nothing, so the builder must not emit it.
const exec = d.querySelector('input[name="mode"][value="exec"]');
exec.checked = true; fire(exec);
$('all-to').value = 'successor@example.com';
fire($('all-to'), 'input');
check('execute mode: not emitted',
      !out().includes('--allow-orphaned-shared-drives'), out());

// OFF-09: combinations the script refuses must disable Copy, and ones it
// accepts must not.
const copyOk = () => !$('copy').disabled;
const setVal = (id, v) => { $(id).value = v; fire($(id), 'input'); };
const tick = (id, on) => { $(id).checked = on; fire($(id)); };

tick('force', true);
tick('unsuspend', true); tick('no-suspend', true);
check('--unsuspend with --no-suspend is refused', !copyOk(), out());
tick('no-suspend', false);
check('--unsuspend alone is accepted', copyOk(), $('validation').textContent);
tick('unsuspend', false);

setVal('restore-batch-size', '1');
check('--restore-batch-size 1 is refused', !copyOk(), out());
setVal('restore-batch-size', '2');
check('--restore-batch-size 2 is accepted', copyOk(), $('validation').textContent);
setVal('restore-batch-size', '');

setVal('all-to', '');
setVal('email-to', 'successor@example.com');
setVal('reuse-email-backup', '/backups/leaver');
check('restore-only with --force and --email-to is accepted',
      copyOk(), $('validation').textContent);
check('restore-only emits --reuse-email-backup and --email-to',
      out().includes('--reuse-email-backup') && out().includes('--email-to'), out());
setVal('reuse-email-backup', '');
setVal('email-to', '');

check('--forward-alias-to help no longer promises an email',
      !d.body.textContent.includes('Sends a summary notice'));

console.log(fails ? `\n${fails} failed` : '\nall passed');
process.exit(fails ? 1 : 0);
