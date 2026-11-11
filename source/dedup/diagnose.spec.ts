import test from 'ava';
import type {Finding} from '../findings/types.js';
import type {ExistingIssue} from '../issues/types.js';
import {diagnoseIssueIdentities} from './diagnose.js';
import {findingHash} from './hash.js';
import {upsertMarker} from './markers.js';
import {planReconciliation} from './plan.js';
import {fullScope} from './scope.js';

console.log('\ndedup/diagnose.spec.ts');

function finding(file: string): Finding {
	return {
		rule: 'p/r',
		file,
		lineRange: {start: 1, end: 2},
		category: 'security',
		severity: 'high',
		confidence: 'medium',
		offendingSnippet: 'x',
	};
}

/** A finding as `auditPack` stamps it: attributed to the pack that ran. */
function attributed(file: string, pack: string, rule: string): Finding {
	return {...finding(file), pack, rule};
}

/** An existing issue carrying the hash of the given finding. */
function issueFor(
	f: Finding,
	overrides: Partial<ExistingIssue> = {},
): ExistingIssue {
	return {
		number: 1,
		url: 'u',
		state: 'open',
		labels: ['sentinel'],
		body: upsertMarker('body', 'hash', findingHash(f)),
		...overrides,
	};
}

/** An issue carrying the hash plus the scope markers a current run writes. */
function markedIssueFor(
	f: Finding,
	pack: string,
	overrides: Partial<ExistingIssue> = {},
): ExistingIssue {
	const base = issueFor(f, overrides);
	return {
		...base,
		body: upsertMarker(upsertMarker(base.body, 'pack', pack), 'path', f.file),
	};
}

/** An issue whose stored hash is one this version would never compute. */
function legacyIssueFor(f: Finding, pack: string): ExistingIssue {
	const marked = markedIssueFor(f, pack);
	return {
		...marked,
		body: upsertMarker(marked.body, 'hash', 'deadbeefdeadbeef'),
	};
}

test('a finding matching the stored hash diagnoses the issue as matched', t => {
	const f = finding('a.rs');
	const [d] = diagnoseIssueIdentities([f], [issueFor(f)]);
	t.is(d?.status, 'matched');
	t.is(d?.matchedBy, f);
});

test('a legacy issue is matched through its recomputed pack/path identity', t => {
	// The stored hash is one this version would never compute; the `pack` and
	// `path` markers still reproduce the identity the run produces.
	const current = attributed('src/db.ts', 'sql', 'sql/whatever');
	const [d] = diagnoseIssueIdentities(
		[current],
		[legacyIssueFor(current, 'sql')],
	);
	t.is(d?.status, 'matched');
	t.is(d?.identityKeys.length, 2, 'stored hash plus recomputed identity');
});

test('an issue matching under two identities is diagnosed once, as matched', t => {
	// Both the stored hash and the recomputed identity resolve to the same
	// finding's hash. The issue is still one issue: one diagnosis, no ageing.
	const f = attributed('src/db.ts', 'sql', 'sql/x');
	const issue = markedIssueFor(f, 'sql');
	const diagnoses = diagnoseIssueIdentities([f], [issue]);
	t.is(diagnoses.length, 1);
	t.is(diagnoses[0]?.status, 'matched');
});

test('an unmatched two-identity issue ages exactly once', t => {
	// The failure this guards: an issue reachable under two keys being aged
	// once per key, reaching the resolve threshold in half the runs.
	const gone = attributed('src/db.ts', 'sql', 'sql/x');
	const diagnoses = diagnoseIssueIdentities([], [legacyIssueFor(gone, 'sql')]);
	t.is(diagnoses.length, 1, 'diagnosed the same issue more than once');
	t.is(diagnoses[0]?.status, 'aging');
	t.is(diagnoses[0]?.missesAfter, 1, 'aged the same issue twice in one pass');
});

test('a closed issue with a suppression label is suppressed', t => {
	const f = finding('a.rs');
	const suppressed = issueFor(f, {
		state: 'closed',
		labels: ['sentinel', 'sentinel:false-positive'],
	});
	const [d] = diagnoseIssueIdentities([f], [suppressed]);
	t.is(d?.status, 'suppressed');
});

test('a suppression label wins over the open state', t => {
	// The label, not the close, is what suppresses: an open issue carrying a
	// suppression label must not read as matched even when its finding recurs.
	const f = finding('a.rs');
	const issue = issueFor(f, {
		state: 'open',
		labels: ['sentinel', 'sentinel:wontfix'],
	});
	const [d] = diagnoseIssueIdentities([f], [issue]);
	t.is(d?.status, 'suppressed');
	t.is(d?.matchedBy, undefined);
});

test('an issue whose file was not read this run is held', t => {
	const gone = finding('unscanned.rs');
	const [d] = diagnoseIssueIdentities([], [markedIssueFor(gone, 'p')], {
		scope: {
			scannedByPack: new Map([['p', new Set(['other.rs'])]]),
			fullPacks: new Set(),
		},
	});
	t.is(d?.status, 'held');
	t.is(d?.missesAfter, undefined, 'a held issue does not age');
});

test('a scanned-but-absent issue ages, with the miss count it would reach', t => {
	const gone = finding('gone.rs');
	const issue = issueFor(gone, {
		body: upsertMarker(
			upsertMarker('body', 'hash', findingHash(gone)),
			'misses',
			'1',
		),
	});
	const [d] = diagnoseIssueIdentities([], [issue], {resolveAfterMisses: 3});
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 2);
	t.is(d?.wouldResolve, false);
});

test('misses landing exactly on the threshold resolve', t => {
	// Boundary: readMisses + 1 === resolveAfterMisses. One run short of this
	// the issue is merely aging; at it, the run would auto-resolve.
	const gone = finding('gone.rs');
	const issue = issueFor(gone, {
		body: upsertMarker(
			upsertMarker('body', 'hash', findingHash(gone)),
			'misses',
			'2',
		),
	});
	const [d] = diagnoseIssueIdentities([], [issue], {resolveAfterMisses: 3});
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 3);
	t.is(d?.wouldResolve, true);
});

test('misses one below the threshold do not resolve', t => {
	const gone = finding('gone.rs');
	const [d] = diagnoseIssueIdentities([], [issueFor(gone)], {
		resolveAfterMisses: 3,
	});
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 1);
	t.is(d?.wouldResolve, false);
});

test('a threshold of one resolves on the first miss', t => {
	const gone = finding('gone.rs');
	const [d] = diagnoseIssueIdentities([], [issueFor(gone)], {
		resolveAfterMisses: 1,
	});
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 1);
	t.is(d?.wouldResolve, true);
});

test('an issue with no markers is ignored', t => {
	const f = finding('a.rs');
	const diagnoses = diagnoseIssueIdentities(
		[f],
		[
			{
				number: 9,
				url: 'u',
				state: 'open',
				labels: ['sentinel'],
				body: 'no marker',
			},
		],
	);
	t.is(diagnoses.length, 1, 'every issue gets a diagnosis');
	t.is(diagnoses[0]?.status, 'ignored');
	t.deepEqual(diagnoses[0]?.identityKeys, []);
});

test('a closed issue without a suppression label is ignored', t => {
	const f = finding('a.rs');
	const closed = issueFor(f, {state: 'closed'});
	const [d] = diagnoseIssueIdentities([f], [closed]);
	t.is(d?.status, 'ignored');
});

test('a model renaming its rule between runs still matches', t => {
	// Identity is pack + file and nothing else: `sql/string-concat` becoming
	// `sql/string-concatenation` must not read as a new finding.
	const run1 = attributed('src/db.ts', 'sql', 'sql/string-concat');
	const run2 = attributed('src/db.ts', 'sql', 'sql/string-concatenation');
	const [d] = diagnoseIssueIdentities([run2], [markedIssueFor(run1, 'sql')]);
	t.is(d?.status, 'matched');
	t.is(d?.matchedBy, run2);
});

test('findings from different packs in the same file stay distinct', t => {
	// Pack A's open issue is not matched by pack B's finding in the same file —
	// from A's perspective its finding did not recur, so it ages.
	const aIssue = markedIssueFor(attributed('src/db.ts', 'sql', 'sql/x'), 'sql');
	const bFinding = attributed('src/db.ts', 'secrets', 'secrets/y');
	const [d] = diagnoseIssueIdentities([bFinding], [aIssue]);
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 1);
});

test('with no scope, diagnosis treats every file as scanned', t => {
	// Planner parity: omitting the scope is the pre-incremental behaviour, so
	// an absent finding ages rather than being held.
	const gone = finding('gone.rs');
	const [d] = diagnoseIssueIdentities([], [markedIssueFor(gone, 'p')]);
	t.is(d?.status, 'aging');
});

test('a full scope changes nothing about ageing', t => {
	const gone = finding('gone.rs');
	const [d] = diagnoseIssueIdentities([], [markedIssueFor(gone, 'p')], {
		scope: fullScope(['p']),
	});
	t.is(d?.status, 'aging');
	t.is(d?.missesAfter, 1);
});

test('diagnosis agrees with the planner on a mixed batch', t => {
	// The diagnostic is the read-only face of the planner: same inputs must
	// sort every issue into the matching plan bucket.
	const recurring = finding('recurring.rs');
	const gone = finding('gone.rs');
	const unscanned = finding('unscanned.rs');
	const suppressedFinding = finding('suppressed.rs');
	const existing = [
		markedIssueFor(recurring, 'p', {number: 1}),
		markedIssueFor(gone, 'p', {number: 2}),
		markedIssueFor(unscanned, 'p', {number: 3}),
		markedIssueFor(suppressedFinding, 'p', {
			number: 4,
			labels: ['sentinel', 'sentinel:accepted'],
		}),
	];
	const findings = [recurring, suppressedFinding];
	const scope = {
		scannedByPack: new Map([
			['p', new Set(['recurring.rs', 'gone.rs', 'suppressed.rs'])],
		]),
		fullPacks: new Set<string>(),
	};
	const options = {resolveAfterMisses: 3, scope};

	const diagnoses = diagnoseIssueIdentities(findings, existing, options);
	const plan = planReconciliation(findings, existing, options);

	const statusByNumber = new Map(
		diagnoses.map(d => [d.issue.number, d.status] as const),
	);
	t.is(statusByNumber.get(1), 'matched');
	t.is(plan.toTouch.length, 1);
	t.is(statusByNumber.get(2), 'aging');
	t.is(plan.toIncrementMiss.length, 1);
	t.is(statusByNumber.get(3), 'held');
	t.is(plan.held.length, 1);
	t.is(statusByNumber.get(4), 'suppressed');
	t.is(plan.suppressed.length, 1);
});
