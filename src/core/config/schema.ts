import { z } from 'zod';

export const toolipConfigSchema = z.object({
  schemaVersion: z.literal('1.0').default('1.0'),
  include: z.array(z.string()).default([]),
  exclude: z.array(z.string()).default([]),
  rules: z
    .record(
      z.object({
        enabled: z.boolean().optional(),
        severity: z
          .enum([
            'critical',
            'high',
            'medium',
            'low',
            'info'
          ])
          .optional(),
        paths: z
          .array(
            z.object({
              pattern: z.string(),
              severity: z
                .enum([
                  'critical',
                  'high',
                  'medium',
                  'low',
                  'info'
                ])
                .optional(),
              enabled: z.boolean().optional()
            })
          )
          .optional()
      })
    )
    .default({}),
  suppressions: z
    .array(
      z.object({
        ruleId: z.string(),
        path: z.string().optional(),
        reason: z.string().min(3),
        expiresAt: z.string().datetime().optional()
      })
    )
    .default([]),
  history: z
    .object({
      enabled: z.boolean().default(true),
      maxEntries: z.number().int().positive().max(5000).default(500)
    })
    .default({
      enabled: true,
      maxEntries: 500
    }),
  providers: z
    .object({
      osv: z
        .object({
          enabled: z.boolean().default(true),
          timeoutMs: z.number().int().positive().default(20000)
        })
        .default({
          enabled: true,
          timeoutMs: 20000
        }),
      depsDev: z
        .object({
          enabled: z.boolean().default(true),
          timeoutMs: z.number().int().positive().default(20000)
        })
        .default({
          enabled: true,
          timeoutMs: 20000
        })
    })
    .default({
      osv: {
        enabled: true,
        timeoutMs: 20000
      },
      depsDev: {
        enabled: true,
        timeoutMs: 20000
      }
    })
});

export type ToolipConfig = z.infer<
  typeof toolipConfigSchema
>;
