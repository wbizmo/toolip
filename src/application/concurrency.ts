export async function mapConcurrent<T, R>(
  items: readonly T[],
  concurrency: number,
  mapper: (item: T, index: number) => Promise<R>,
  signal?: AbortSignal
): Promise<R[]> {
  if (items.length === 0) return [];
  if (signal?.aborted) throw cancellationError(signal);

  const results = new Array<R>(items.length);
  const requested = Number.isFinite(concurrency) ? Math.floor(concurrency) : 1;
  const limit = Math.max(1, Math.min(requested, items.length));
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      if (signal?.aborted) throw cancellationError(signal);
      const index = cursor++;
      if (index >= items.length) return;
      const result = await mapper(items[index] as T, index);
      if (signal?.aborted) throw cancellationError(signal);
      results[index] = result;
    }
  };

  const settled = await Promise.allSettled(
    Array.from({ length: limit }, () => worker())
  );
  const failure = settled.find(
    (result): result is PromiseRejectedResult => result.status === 'rejected'
  );
  if (failure) throw failure.reason;

  return results;
}

function cancellationError(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  const error = new Error('Operation was cancelled.');
  error.name = 'AbortError';
  return error;
}
