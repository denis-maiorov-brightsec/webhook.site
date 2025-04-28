import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('ANY /any', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'id_enumeration', 'unvalidated_redirect', 'xss'],
      attackParamLocations: [
        AttackParamLocation.HEADER,
        AttackParamLocation.QUERY,
        AttackParamLocation.BODY
      ]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST, // Using POST as a representative method for ANY
      url: `${baseUrl}/any`,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': '<request-uuid>',
        'X-Token-Id': '<token-uuid>'
      },
      query: {
        sorting: 'oldest',
        page: '1',
        per_page: '50'
      },
      body: {
        key: 'value'
      }
    });
});
