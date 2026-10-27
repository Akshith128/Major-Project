import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { enableSpotlight } from './lib/spotlight';
import { applyTheme, storedTheme } from './lib/theme';
import './index.css';

applyTheme(storedTheme()); // before first paint, so there is no flash of the wrong theme
enableSpotlight();

createRoot(document.getElementById('root')!).render(<App />);
