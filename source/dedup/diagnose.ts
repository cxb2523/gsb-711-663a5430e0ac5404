/**
 * Dedup identity diagnosis. Given this run's findings and the issues that
 * already exist on the target repo, explain — per issue — which identity
 * state the reconciler sees it in, without changing anything: matched (a
 * finding this run claims one of its identity keys), suppressed (it carries a
 * suppression label), held (its file was outside this run's scan scope, so its
 * absence proves nothing), or aging (it was scanned and did not recur, so its
 * miss counter would move — possibly to the auto-resolve threshold).
 *
 * This is the read-only counterpart of `planReconciliation`: same identity
 * keys, same suppression labels, same scope test, same miss arithmetic, so a
 * diagnosis never disagrees with the plan it describes. It exists so tooling
 * (dry-run previews, dashboards, debugging a surprise close) can answer "why
 * does Sentinel think this issue is stale?" without replaying a run. Pure —
 * no I/O, no network, no clock.
 */

import type {Finding} from '../findings/types.js';
import type {ExistingIssue} from '../issues/types.js';
import {findingHash} from './hash.js';
import {readMarker, readMisses} from './markers.js';
import {hasSuppressionLabel, identityKeysOf} from './plan.js';
import {issueWasScanned, type ScanScope} from './scope.js';

/** The identity state one existing issue is in, from this run's perspective. */
export type IssueIdentityStatus =
	| 'matched'
	| 'suppressed'
	| 'held'
	| 'aging'
	| 'ignored';

/** The diagnosis for one existing issue. */
export interface IssueDiagnosis {
	/** The issue this diagnosis is about. */
	issue: ExistingIssue;
	status: IssueIdentityStatus;
	/**
	 * Every identity key the issue can be matched on — its stored hash plus
	 * the identity recomputed from its own `pack`/`path` markers. Empty when
	 * the issue carries no markers Sentinel recognises.
	 */
	identityKeys: string[];
	/** The finding that matched, when `status` is `matched`. */
	matchedBy?: Finding;
	/** When `aging`: the miss count after this run's increment. */
	missesAfter?: number;
	/** When `aging`: whether `missesAfter` reaches the resolve threshold. */
	wouldResolve?: boolean;
}

/** Options for diagnosis. Mirrors {@link ReconcileOptions}. */
export interface DiagnoseOptions {
	/** Consecutive absent runs before an open issue is auto-resolved. Min 1. */
	resolveAfterMisses?: number;
	/**
	 * What this run actually read. Omit when every file was read — diagnosis
	 * then behaves exactly as the planner did before scope existed.
	 */
	scope?: ScanScope;
}

/**
 * Diagnose the identity state of every existing issue against this run's
 * findings.
 *
 * Each issue is diagnosed exactly once, however many identity keys it carries:
 * an issue reachable under both its stored hash and its recomputed identity
 * is matched once, and — like the planner — can never be aged twice in one
 * pass. Precedence follows the planner: suppression labels beat the open
 * state, matching beats holding, and holding beats ageing. Issues Sentinel
 * cannot act on (no identity markers, or closed without a suppression label)
 * are reported as `ignored` rather than dropped, so the output always covers
 * the input one-for-one.
 */
export function diagnoseIssueIdentities(
	findings: Finding[],
	existing: ExistingIssue[],
	options: DiagnoseOptions = {},
): IssueDiagnosis[] {
	const resolveAfterMisses = Math.max(1, options.resolveAfterMisses ?? 3);

	// Deduplicate findings within this run by hash, exactly as the planner
	// does; first occurrence wins.
	const findingByHash = new Map<string, Finding>();
	for (const finding of findings) {
		const hash = findingHash(finding);
		if (!findingByHash.has(hash)) {
			findingByHash.set(hash, finding);
		}
	}

	const diagnoses: IssueDiagnosis[] = [];
	for (const issue of existing) {
		const keys = identityKeysOf(issue);
		if (keys.length === 0) {
			// No markers, no identity: the planner skips these entirely.
			diagnoses.push({issue, status: 'ignored', identityKeys: keys});
			continue;
		}
		// The label, not the close, is what suppresses — an open issue carrying
		// a suppression label is suppressed, not matched or aged.
		if (hasSuppressionLabel(issue)) {
			diagnoses.push({issue, status: 'suppressed', identityKeys: keys});
			continue;
		}
		if (issue.state !== 'open') {
			// Closed without a suppression label: nothing to reconcile.
			diagnoses.push({issue, status: 'ignored', identityKeys: keys});
			continue;
		}
		const matchedKey = keys.find(key => findingByHash.has(key));
		if (matchedKey !== undefined) {
			diagnoses.push({
				issue,
				status: 'matched',
				identityKeys: keys,
				matchedBy: findingByHash.get(matchedKey),
			});
			continue;
		}
		if (
			!issueWasScanned(
				options.scope,
				readMarker(issue.body, 'pack'),
				readMarker(issue.body, 'path'),
			)
		) {
			diagnoses.push({issue, status: 'held', identityKeys: keys});
			continue;
		}
		const missesAfter = readMisses(issue.body) + 1;
		diagnoses.push({
			issue,
			status: 'aging',
			identityKeys: keys,
			missesAfter,
			wouldResolve: missesAfter >= resolveAfterMisses,
		});
	}
	return diagnoses;
}
