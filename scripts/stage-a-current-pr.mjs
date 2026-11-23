const validSha = (value) => /^[a-f0-9]{40}$/iu.test(value ?? '');

const pause = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

/**
 * GitHub may publish updated base/head fields before rebuilding a PR's
 * synthetic merge commit. Wait for the authenticated commit object to contain
 * the exact event base and head; never approve a stale merge object.
 */
export async function resolveCurrentPullRequestMergeIdentity({
  expectedBaseSha,
  expectedHeadSha,
  getPullRequest,
  getCommit,
  wait = pause,
  attempts = 8,
  retryDelayMs = 1_000
}) {
  if (
    !validSha(expectedBaseSha) ||
    !validSha(expectedHeadSha) ||
    typeof getPullRequest !== 'function' ||
    typeof getCommit !== 'function' ||
    typeof wait !== 'function' ||
    !Number.isSafeInteger(attempts) ||
    attempts < 1 ||
    attempts > 8 ||
    !Number.isSafeInteger(retryDelayMs) ||
    retryDelayMs < 0 ||
    retryDelayMs > 5_000
  )
    throw new Error('Stage A merge identity resolver configuration is invalid');

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await getPullRequest();
    const pullRequest = response?.data;
    const baseSha = pullRequest?.base?.sha;
    const headSha = pullRequest?.head?.sha;
    if (baseSha !== expectedBaseSha || headSha !== expectedHeadSha)
      throw new Error(
        'Current pull request base/head no longer match the triggering event'
      );

    const mergeSha = pullRequest?.merge_commit_sha;
    if (validSha(mergeSha)) {
      try {
        const commitResponse = await getCommit(mergeSha);
        const parents = commitResponse?.data?.parents;
        if (
          Array.isArray(parents) &&
          parents.some((parent) => parent?.sha === baseSha) &&
          parents.some((parent) => parent?.sha === headSha)
        )
          return { baseSha, headSha, mergeSha };
      } catch (error) {
        if (![404, 422].includes(error?.status)) throw error;
      }
    }

    if (attempt + 1 < attempts) await wait(retryDelayMs);
  }

  throw new Error(
    'Current pull request merge commit is not ready for the event base/head'
  );
}
