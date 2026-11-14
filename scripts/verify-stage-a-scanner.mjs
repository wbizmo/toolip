#!/usr/bin/env node
import { trustedScannerDigest } from './stage-a-gate.mjs';

const expected = process.env.TOOLIP_STAGE_A_SHA256;
if (!/^[0-9a-f]{64}$/iu.test(expected ?? ''))
  throw new Error('Protected workflow did not pin the trusted scanner digest.');
const actual = await trustedScannerDigest();
if (actual !== expected.toLowerCase())
  throw new Error(
    'Trusted Stage A scanner digest differs from the protected workflow pin.'
  );
process.stdout.write(`Trusted Stage A digest verified: ${actual}\n`);
