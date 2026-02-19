import * as benchmark from 'benchmark';
import { addEnforcerBenchmarks } from './enforcer_benchmark';
import { addCachedEnforcerBenchmarks } from './cached_enforcer_benchmark';
import { addManagementApiBenchmarks } from './management_api_benchmark';
import { addRoleManagerBenchmarks } from './role_manager_benchmark';

const suite = new benchmark.Suite();

(async () => {
  console.error('Running benchmarks...');

  // Add all benchmarks
  await addEnforcerBenchmarks(suite);
  await addCachedEnforcerBenchmarks(suite);
  await addManagementApiBenchmarks(suite);
  await addRoleManagerBenchmarks(suite);

  const results: any[] = [];

  suite
    .on('cycle', (event: any) => {
      console.error(String(event.target));
      results.push({
        benchmark: event.target.name,
        primaryMetric: {
          score: event.target.hz,
          scoreUnit: 'ops/s',
        },
        iterationCount: event.target.count,
      });
    })
    .on('complete', function (this: any) {
      console.error('Benchmark finished.');
      console.log(JSON.stringify(results, null, 2));
    })
    .run({ async: true });
})();
