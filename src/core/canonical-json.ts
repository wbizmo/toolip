const MAX_CANONICAL_DEPTH = 256;
const MAX_CANONICAL_NODES = 1_000_000;
const MAX_CANONICAL_BYTES = 32 * 1024 * 1024;

type CanonicalBudget = { nodes: number; bytes: number };
interface NormalizedJsonObject {
  [key: string]: NormalizedJson;
}

type NormalizedJson =
  | null
  | boolean
  | number
  | string
  | NormalizedJson[]
  | NormalizedJsonObject;

function consume(budget: CanonicalBudget, bytes: number): void {
  budget.bytes += bytes;
  if (budget.bytes > MAX_CANONICAL_BYTES)
    throw new RangeError('Canonical JSON exceeds the size budget.');
}

function encodeString(value: string, budget?: CanonicalBudget): string {
  // Any UTF-16 code unit can expand to at most six ASCII bytes when escaped.
  // Bound before JSON.stringify allocates the escaped copy.
  if (value.length > Math.floor((MAX_CANONICAL_BYTES - 2) / 6))
    throw new RangeError('Canonical JSON exceeds the size budget.');
  const encoded = JSON.stringify(value);
  if (budget) consume(budget, Buffer.byteLength(encoded, 'utf8'));
  return encoded;
}

function normalize(
  value: unknown,
  budget: CanonicalBudget,
  ancestors: WeakSet<object>,
  depth: number
): NormalizedJson {
  if (depth > MAX_CANONICAL_DEPTH)
    throw new RangeError('Canonical JSON exceeds the nesting budget.');
  if (++budget.nodes > MAX_CANONICAL_NODES)
    throw new RangeError('Canonical JSON exceeds the node budget.');

  if (value === null) {
    consume(budget, 4);
    return null;
  }
  if (typeof value === 'string') {
    encodeString(value, budget);
    return value;
  }
  if (typeof value === 'boolean') {
    consume(budget, value ? 4 : 5);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value))
      throw new TypeError(
        'Canonical JSON does not support non-finite numbers.'
      );
    consume(budget, Buffer.byteLength(JSON.stringify(value), 'utf8'));
    return value;
  }
  if (typeof value !== 'object')
    throw new TypeError('Canonical JSON contains an unsupported value.');

  if (ancestors.has(value))
    throw new TypeError('Canonical JSON does not support cyclic values.');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype)
        throw new TypeError('Canonical JSON requires plain arrays.');
      const length = value.length;
      if (budget.nodes + length > MAX_CANONICAL_NODES)
        throw new RangeError('Canonical JSON exceeds the node budget.');

      for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== 'string')
          throw new TypeError('Canonical JSON does not support symbol keys.');
        if (key === 'length') continue;
        const index = Number(key);
        if (
          !Number.isInteger(index) ||
          index < 0 ||
          index >= length ||
          String(index) !== key
        )
          throw new TypeError('Canonical JSON requires plain arrays.');
      }

      consume(budget, 2 + Math.max(0, length - 1));
      const result: NormalizedJson[] = [];
      for (let index = 0; index < length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !('value' in descriptor))
          throw new TypeError(
            'Canonical JSON arrays must contain enumerable data values.'
          );
        result.push(normalize(descriptor.value, budget, ancestors, depth + 1));
      }
      return result;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      throw new TypeError('Canonical JSON requires plain objects.');

    const keys = Reflect.ownKeys(value);
    if (budget.nodes + keys.length > MAX_CANONICAL_NODES)
      throw new RangeError('Canonical JSON exceeds the node budget.');
    const entries: Array<[string, unknown]> = [];
    for (const key of keys) {
      if (typeof key !== 'string')
        throw new TypeError('Canonical JSON does not support symbol keys.');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor))
        throw new TypeError(
          'Canonical JSON objects must contain enumerable data values.'
        );
      if (descriptor.value !== undefined) entries.push([key, descriptor.value]);
    }
    entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));

    // Include braces, colons and commas in the output budget. A null
    // prototype keeps `__proto__` an ordinary signed property.
    consume(budget, 2 + entries.length * 2 + Math.max(0, entries.length - 1));
    const result = Object.create(null) as NormalizedJsonObject;
    for (const [key, entryValue] of entries) {
      encodeString(key, budget);
      result[key] = normalize(entryValue, budget, ancestors, depth + 1);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

function serialize(value: NormalizedJson): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return encodeString(value);
  if (typeof value === 'number' || typeof value === 'boolean')
    return JSON.stringify(value);
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let index = 0; index < value.length; index++) {
      const item = value[index];
      if (item === undefined)
        throw new TypeError('Canonical JSON contains a sparse array.');
      items.push(serialize(item));
    }
    return `[${items.join(',')}]`;
  }

  const keys = Object.keys(value).sort();
  const entries: string[] = [];
  for (const key of keys) {
    const item = value[key];
    if (item === undefined)
      throw new TypeError('Canonical JSON contains an unsupported value.');
    entries.push(`${encodeString(key)}:${serialize(item)}`);
  }
  return `{${entries.join(',')}}`;
}

/** Stable JSON with bounded depth, node count and serialized byte size. */
export function canonicalJson(value: unknown): string {
  const normalized = normalize(value, { nodes: 0, bytes: 0 }, new WeakSet(), 0);
  const canonical = serialize(normalized);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CANONICAL_BYTES)
    throw new RangeError('Canonical JSON exceeds the size budget.');
  return canonical;
}
