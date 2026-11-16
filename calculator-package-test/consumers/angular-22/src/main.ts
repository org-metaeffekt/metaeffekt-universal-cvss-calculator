import { bootstrapApplication } from '@angular/platform-browser';
import { ScorePanelComponent } from './app/score-panel.component';

bootstrapApplication(ScorePanelComponent).catch((error: unknown) => console.error(error));
