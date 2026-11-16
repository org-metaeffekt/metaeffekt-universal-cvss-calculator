import { summarize } from './summary.ts';

const summary = summarize('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
if (summary?.score !== '9.8' || summary.severity !== 'CRITICAL') {
  throw new Error(`Expected 9.8 CRITICAL, got ${JSON.stringify(summary)}`);
}

console.log(`typescript-7 nodenext: CVSS 3.1 ${summary.score} ${summary.severity}`);
