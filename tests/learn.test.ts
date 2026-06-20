import { describe, expect, it } from 'vitest';
import { getLearnTopic, listLearnTopics } from '../src/core/learn.js';

describe('learn', () => {
  it('lists learning topics', () => {
    const topics = listLearnTopics();

    expect(topics.length).toBeGreaterThanOrEqual(7);
    expect(topics.map((topic) => topic.id)).toContain('cors');
    expect(topics.map((topic) => topic.id)).toContain('jwt');
    expect(topics.map((topic) => topic.id)).toContain('secrets');
  });

  it('gets a known topic', () => {
    const topic = getLearnTopic('cors');

    expect(topic?.title).toBe('CORS Security');
    expect(topic?.risks.length).toBeGreaterThan(0);
  });

  it('returns null for unknown topics', () => {
    expect(getLearnTopic('unknown')).toBeNull();
  });
});
