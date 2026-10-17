# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Shared caller/profile data contract and host-only failure reporting."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import yaml

from scripts import agent_review_contract as contract
from scripts import pr_agent_review as adapter

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.load((ROOT / '.github/workflows/agent-review-reusable.yaml').read_text(), Loader=yaml.BaseLoader)
SHA = 'a' * 40


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Resolve platform temp symlinks such as macOS /var -> /private/var; the reader refuses symlinked paths.
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'profile.toml'
        self.good = '[review]\ninstructions="Review correctness"\n[ignore]\nglob=["**/vendor/**"]\n'
        self.path.write_text(self.good)

    def test_only_instructions_and_exclusions_are_supported(self):
        data, digest = contract.load_profile(self.path)
        self.assertEqual(hashlib.sha256(self.good.encode()).hexdigest(), digest)
        self.assertEqual(['**/vendor/**'], data['ignore']['glob'])
        for attack in ('\n[config]\nmodel="other"', '\n[github]\nuser_token="fixture"',
                       '\n[litellm]\nenable_callbacks=true', '\n[review.extra]\nkey=true'):
            with self.subTest(attack=attack):
                self.path.write_text(self.good + attack)
                with self.assertRaises(ValueError):
                    contract.load_profile(self.path)
        for attack in (self.good.replace('instructions=', 'unknown='),
                       self.good.replace('"Review correctness"', 'false'),
                       self.good.replace('"Review correctness"', '""'),
                       self.good.replace('["**/vendor/**"]', '"**/vendor/**"'),
                       self.good.replace('["**/vendor/**"]', '[false]'),
                       self.good.replace('["**/vendor/**"]', '[""]'),
                       '[review]\ninstructions="only one section"', 'not toml'):
            with self.subTest(attack=attack):
                self.path.write_text(attack)
                with self.assertRaises(ValueError):
                    contract.load_profile(self.path)

    def test_reader_rejects_oversize_nonregular_and_symlink_components(self):
        self.path.write_bytes(b'x' * contract.MAX_DATA_BYTES)
        self.assertEqual(contract.MAX_DATA_BYTES, len(contract.read_data(self.path)))
        self.path.write_bytes(b'x' * (contract.MAX_DATA_BYTES + 1))
        with self.assertRaises(ValueError):
            contract.read_data(self.path)
        # Valid content, so only path refusal can make the following reads fail.
        self.path.write_text(self.good)
        self.assertEqual(self.good, contract.read_data(self.path))
        with self.assertRaises(ValueError):
            contract.read_data(self.root / '..' / self.root.name / 'profile.toml')
        link = self.root / 'link'
        link.symlink_to(self.path)
        directory = self.root / 'directory'
        directory.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        for path in (link, directory / 'profile.toml', self.root, fifo):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                contract.read_data(path)
        self.path.write_bytes(b'\xff')
        with self.assertRaises(UnicodeError):
            contract.read_data(self.path)

    def test_pipelock_profile_preserves_included_source_and_declared_exclusions(self):
        import fnmatch
        data, _ = contract.load_profile(ROOT / '.github/agent-review.toml')
        globs = data['ignore']['glob']
        for path, excluded in [('internal/scanner/scanner.go', False), ('scripts/pr_agent_review.py', False),
                               ('internal/scanner/testdata/fixture.json', True), ('api/example.pb.go', True),
                               ('web/package-lock.json', True)]:
            with self.subTest(path=path):
                self.assertEqual(excluded, any(fnmatch.fnmatch(path, g) for g in globs))
        self.assertIn('Core literal-IP SSRF', data['review']['instructions'])


class CallerTests(unittest.TestCase):
    def test_exact_local_and_pinned_remote_templates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'caller.yaml'
            path.write_text(contract.EXPECTED_CALLER)
            contract.validate_caller(path, SHA, allow_local=True)
            with self.assertRaises(ValueError):
                contract.validate_caller(path, SHA)
            remote = contract.EXPECTED_CALLER.replace(contract.LOCAL_CALL, contract.REMOTE_CALL + SHA + ' # main')
            path.write_text(remote)
            contract.validate_caller(path, SHA)
            mutations = [remote.replace(SHA, 'main'), remote.replace(SHA, 'b' * 40),
                         remote.replace("github.event.comment.user.id == 142104046 &&", ''),
                         remote.replace("github.run_attempt == '1' &&", ''),
                         remote.replace("github.event.comment.author_association == 'MEMBER' &&", ''),
                         remote.replace("github.event.comment.user.type == 'User' &&", ''),
                         remote.replace("'/agent-review'", "'/agent-review deep'"),
                         remote.replace('types: [created]', 'types: [created, edited]'),
                         remote.replace('pull-requests: write', 'pull-requests: read'),
                         remote.replace('    secrets:\n', '    secrets: inherit\n    ignored:\n'),
                         remote + '\n    env:\n      PYTHONPATH: proposed\n']
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    path.write_text(mutation)
                    with self.assertRaises(ValueError):
                        contract.validate_caller(path, SHA)
            path.write_text(remote)
            with self.assertRaises(ValueError):
                contract.validate_caller(path, 'main')
        self.assertEqual(contract.EXPECTED_CALLER, (ROOT / '.github/workflows/agent-review.yaml').read_text())

    def test_contract_binds_the_running_caller_file(self):
        repo = 'example/project'
        contract.validate_caller_ref(f'{repo}/.github/workflows/agent-review.yaml@refs/heads/main', repo)
        for ref in (None, '', f'{repo}/.github/workflows/agent-review.yaml@',
                    f'{repo}/.github/workflows/other.yaml@refs/heads/main',
                    f'{repo}/.github/workflows/agent-review.yaml.bak@refs/heads/main',
                    f'{repo}/.github/workflows/agent-review.yaml@decoy.yaml@refs/heads/main',
                    f'{repo}/.github/workflows/agent-review.yaml@refs/heads/x.yaml@refs/heads/main',
                    f'{repo}/.github/workflows/agent-review.yaml@refs/tags/v1',
                    f'{repo}/.github/workflows/agent-review.yaml@refs/heads/',
                    f'{repo}/.github/workflows/agent-review.yaml@refs/heads/main x',
                    f'example/other/.github/workflows/agent-review.yaml@refs/heads/main',
                    f'x{repo}/.github/workflows/agent-review.yaml@refs/heads/main'):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                contract.validate_caller_ref(ref, repo)
        for bad_repo in (None, '', 'example', 'example/project/extra'):
            with self.subTest(repo=bad_repo), self.assertRaises(ValueError):
                contract.validate_caller_ref(f'{bad_repo}/.github/workflows/agent-review.yaml@refs/heads/main', bad_repo)
        step = WORKFLOW['jobs']['review']['steps'][2]
        self.assertEqual('${{ github.workflow_ref }}', step['env']['CALLER_WORKFLOW_REF'])
        # A matching caller file and profile still fail when another file is running.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / '.github/workflows').mkdir(parents=True)
            (root / '.github/workflows/agent-review.yaml').write_text(
                contract.EXPECTED_CALLER.replace(contract.LOCAL_CALL, contract.REMOTE_CALL + SHA + ' # main'))
            (root / '.github/agent-review.toml').write_text('[review]\ninstructions="Review correctness"\n[ignore]\nglob=[]\n')
            argv = ['agent_review_contract.py', '--root', str(root), '--source-sha', SHA]
            for ref, code in ((f'{repo}/.github/workflows/agent-review.yaml@refs/heads/main', None),
                              (f'{repo}/.github/workflows/decoy-caller.yaml@refs/heads/main', 1)):
                with (self.subTest(ref=ref), patch('sys.argv', argv),
                      patch.dict(os.environ, {'GITHUB_REPOSITORY': repo, 'CALLER_WORKFLOW_REF': ref}),
                      patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO())):
                    if code is None:
                        contract.main()
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            contract.main()
                        self.assertEqual(code, raised.exception.code)

    def test_every_job_repeats_the_exact_admission_gate(self):
        gate = WORKFLOW['jobs']['admit']['if']
        self.assertEqual(gate, WORKFLOW['jobs']['source']['if'])
        self.assertTrue(WORKFLOW['jobs']['notify-failure']['if'].startswith('always() && ' + gate + ' && ('))

    def test_source_binding_and_queue_precede_provider_work(self):
        source = WORKFLOW['jobs']['source']
        self.assertEqual('./.github/workflows/pr-review-source.yaml', source['uses'])
        self.assertEqual({}, source['permissions'])
        self.assertNotIn('secrets', source)
        self.assertEqual('source', WORKFLOW['jobs']['admit']['needs'])
        job = WORKFLOW['jobs']['review']
        self.assertEqual('max', job['concurrency']['queue'])
        self.assertEqual('false', job['concurrency']['cancel-in-progress'])
        run = job['steps'][-1]
        self.assertEqual('${{ needs.source.outputs.reviewer_sha }}', run['env']['REVIEW_SOURCE_SHA'])
        self.assertEqual('${{ github.workflow_sha }}', run['env']['REVIEW_PROFILE_SHA'])
        self.assertEqual('trusted-agent-profile/.github/agent-review.toml', run['env']['REVIEW_PROFILE_PATH'])


class ReuseTests(unittest.TestCase):
    def test_only_bot_owned_terminal_success_is_reusable(self):
        key = 'a' * 64
        summary = NS(id=7, body='Complete review', user=NS(login='github-actions[bot]', type='Bot'))
        digest = hashlib.sha256(summary.body.encode()).hexdigest()
        good = NS(id=8, user=NS(login='github-actions[bot]', type='Bot'),
                  body=f'<!-- agent-review-status:v1 state=success key={key} summary=7 digest={digest} -->\nComplete',
                  html_url='summary')
        self.assertIs(good, adapter.completed_review([good, summary], key))
        for field, value in [('login', 'contributor'), ('type', 'User')]:
            bad = copy.deepcopy(good)
            setattr(bad.user, field, value)
            self.assertIsNone(adapter.completed_review([bad, summary], key))
        self.assertIsNone(adapter.completed_review([good], key))
        for body in [good.body.replace('success', 'running'), good.body.replace('success', 'failed'),
                     good.body.replace(key, 'b' * 64), 'quoted\n' + good.body]:
            bad = copy.deepcopy(good)
            bad.body = body
            self.assertIsNone(adapter.completed_review([bad, summary], key))
        summary.body = 'A later review replaced this summary'
        self.assertIsNone(adapter.completed_review([good, summary], key))
        summary.body = 'Complete review'
        summary.user = None
        self.assertIsNone(adapter.completed_review([good, summary], key))

    def test_profile_exclusions_remain_literal_in_provenance(self):
        text = adapter.provenance('a' * 40, 'b' * 40, 'c' * 64, ['**/`[name](example)/**'])
        self.assertIn('\\u0060', text)
        self.assertNotIn('`[name]', text)

    def test_identity_changes_with_repository_snapshot_source_profile_or_model(self):
        settings = NS(config=NS(model='gpt-6-luna', fallback_models=[]))
        env = {'REVIEW_SOURCE_SHA': 'c' * 40, 'REVIEW_PROFILE_SHA': 'd' * 40}
        with patch.dict(os.environ, env):
            original = adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)[0]
            self.assertEqual(original, adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)[0])
            for args in [('example/other', '1', 'a' * 40, 'b' * 40), ('example/project', '2', 'a' * 40, 'b' * 40),
                         ('example/project', '1', 'e' * 40, 'b' * 40), ('example/project', '1', 'a' * 40, 'e' * 40)]:
                self.assertNotEqual(original, adapter.review_binding(settings, *args)[0])
            with patch.dict(os.environ, REVIEW_SOURCE_SHA='e' * 40):
                self.assertNotEqual(original, adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)[0])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory).resolve() / 'profile.toml'
                path.write_text('[review]\ninstructions="Other review"\n[ignore]\nglob=[]\n')
                with patch.dict(os.environ, REVIEW_PROFILE_PATH=str(path)):
                    self.assertNotEqual(original, adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)[0])
            settings.config.model = 'anthropic/claude-sonnet-5-5'
            self.assertNotEqual(original, adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)[0])
            with patch.dict(os.environ, REVIEW_SOURCE_SHA='main'), self.assertRaises(adapter.ReviewAbort):
                adapter.review_binding(settings, 'example/project', '1', 'a' * 40, 'b' * 40)


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.event_path = Path(self.temp.name).resolve() / 'event.json'
        self.event = {'action': 'created', 'repository': {'full_name': 'example/project'},
                      'issue': {'number': 1, 'pull_request': {'url': 'untrusted'}},
                      'comment': {'body': '/agent-review', 'author_association': 'MEMBER',
                                  'user': {'login': 'luckyPipewrench', 'id': 142104046, 'type': 'User'}}}
        self.env = {'GITHUB_EVENT_PATH': str(self.event_path), 'GITHUB_EVENT_NAME': 'issue_comment',
                    'GITHUB_REPOSITORY': 'example/project', 'GITHUB_ACTOR': 'luckyPipewrench',
                    'GITHUB_ACTOR_ID': '142104046', 'GITHUB_TRIGGERING_ACTOR': 'luckyPipewrench',
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123', 'GH_TOKEN': 'fixture',
                    'REVIEW_HEAD': 'a' * 40, 'REVIEW_BASE': 'b' * 40, 'ADMISSION_RESULT': 'success'}
        self.pr = {'state': 'open', 'head': {'repo': {'full_name': 'example/project', 'fork': False}, 'sha': 'a' * 40},
                   'base': {'repo': {'full_name': 'example/project'}, 'sha': 'b' * 40}}
        self.comments = []
        self.calls = []

    def execute(self, error=None):
        script = WORKFLOW['jobs']['notify-failure']['steps'][0]['run'].split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        self.event_path.write_text(json.dumps(self.event))

        def request(req):
            self.calls.append((req.method, req.full_url, json.loads(req.data) if req.data else None))
            if error:
                raise error
            if req.full_url.endswith('/pulls/1'):
                result = self.pr
            elif req.method == 'GET':
                result = self.comments
            else:
                result = {'id': 7}
            return io.BytesIO(json.dumps(result).encode())

        with patch.dict(os.environ, self.env), patch('urllib.request.urlopen', side_effect=request):
            exec(compile(script, '<trusted-reporter>', 'exec'), {})

    def test_reporter_is_host_only_and_minimally_privileged(self):
        job = WORKFLOW['jobs']['notify-failure']
        self.assertEqual(['source', 'admit', 'review'], job['needs'])
        self.assertIn('always()', job['if'])
        self.assertEqual({'pull-requests': 'write'}, job['permissions'])
        self.assertNotIn('container', job)
        text = json.dumps(job)
        for denied in ('secrets.', 'checkout', 'download-artifact', 'pr_agent_review.py'):
            self.assertNotIn(denied, text)

    def test_failure_is_visible_and_existing_per_run_bot_notice_is_updated(self):
        self.execute()
        self.assertEqual('POST', self.calls[-1][0])
        body = self.calls[-1][2]['body']
        self.assertIn('incomplete', body)
        self.assertIn('/actions/runs/123', body)
        self.assertNotIn('fixture', body)
        self.assertIn('a' * 40, body)
        self.comments = [{'id': 7, 'body': body, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'}}]
        self.execute()
        self.assertEqual('PATCH', self.calls[-1][0])
        self.comments[0]['user']['login'] = 'contributor'
        self.execute()
        self.assertEqual('POST', self.calls[-1][0])

    def test_admission_and_stale_snapshot_have_fixed_messages(self):
        self.env.update(REVIEW_HEAD='', REVIEW_BASE='', ADMISSION_RESULT='failure')
        self.execute()
        self.assertIn('never started', self.calls[-1][2]['body'])
        self.env.update(REVIEW_HEAD='c' * 40, REVIEW_BASE='b' * 40, ADMISSION_RESULT='success')
        self.execute()
        self.assertIn('commits changed', self.calls[-1][2]['body'])
        with self.assertRaisesRegex(SystemExit, '^Review failure notification failed; inspect Actions status$'):
            self.execute(error=RuntimeError('private provider detail'))

    def test_unauthorized_edited_rerun_issue_fork_and_closed_requests_do_not_comment(self):
        original = copy.deepcopy(self.event)
        for change in ('identity', 'command', 'edited', 'issue', 'bot', 'association'):
            self.event = copy.deepcopy(original)
            if change == 'identity':
                self.event['comment']['user']['id'] = 123
            elif change == 'command':
                self.event['comment']['body'] += ' deep'
            elif change == 'edited':
                self.event['action'] = 'edited'
            elif change == 'issue':
                self.event['issue'].pop('pull_request')
            elif change == 'bot':
                self.event['comment']['user']['type'] = 'Bot'
            else:
                self.event['comment']['author_association'] = 'CONTRIBUTOR'
            self.calls.clear()
            self.execute()
            self.assertEqual([], self.calls, change)
        self.event = original
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        self.calls.clear()
        self.execute()
        self.assertEqual([], self.calls)
        self.env['GITHUB_RUN_ATTEMPT'] = '1'
        for change in ('fork', 'closed', 'missing', 'other'):
            self.calls.clear()
            self.pr['state'] = 'closed' if change == 'closed' else 'open'
            self.pr['head']['repo'] = None if change == 'missing' else {
                'full_name': 'other/project' if change == 'other' else 'example/project', 'fork': change == 'fork'}
            self.execute()
            self.assertEqual(['GET'], [c[0] for c in self.calls], change)


if __name__ == '__main__':
    unittest.main()
