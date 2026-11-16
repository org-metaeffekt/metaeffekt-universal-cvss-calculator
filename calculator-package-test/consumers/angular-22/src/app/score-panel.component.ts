import { Component } from '@angular/core';
import { Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';
import type {
  ComponentCategory,
  VectorComponent,
  VectorComponentValue,
} from 'ae-cvss-calculator/dist/types/src/CvssVector';

interface CategorySummary {
  name: string;
  metricCount: number;
  valueCount: number;
}

@Component({
  selector: 'app-score-panel',
  template: `<p>score:{{ overall }}</p>
    @for (summary of summaries; track summary.name) {
      <p>{{ summary.name }}: {{ summary.metricCount }} metrics, {{ summary.valueCount }} values</p>
    }`,
})
export class ScorePanelComponent {
  private vector: Cvss3P1 | Cvss4P0 = new Cvss3P1('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

  get overall(): number {
    return this.vector.calculateScores().overall;
  }

  get summaries(): CategorySummary[] {
    const summaries: CategorySummary[] = [];
    this.vector.getRegisteredComponents().forEach(
      (components: VectorComponent<VectorComponentValue>[], category: ComponentCategory) => {
        summaries.push({
          name: category.name,
          metricCount: components.length,
          valueCount: components.reduce((sum, component) => sum + component.values.length, 0),
        });
      }
    );
    return summaries;
  }

  useVersion(version: '3.1' | '4.0', text?: string): void {
    this.vector = version === '4.0' ? new Cvss4P0(text) : new Cvss3P1(text);
  }
}
