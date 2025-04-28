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

test('ANY /200', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'id_enumeration', 'sqli', 'xss', 'unvalidated_redirect'],
      attackParamLocations: [
        AttackParamLocation.HEADER,
        AttackParamLocation.QUERY,
        AttackParamLocation.BODY
      ]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST, // Using POST as the example method
      url: `${baseUrl}/200`,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': '123e4567-e89b-12d3-a456-426614174000',
        'X-Token-Id': '123e4567-e89b-12d3-a456-426614174000'
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
