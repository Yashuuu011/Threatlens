import '@testing-library/jest-dom';

// Polyfill ResizeObserver for Recharts in JSDOM environment
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

window.ResizeObserver = ResizeObserverMock;

