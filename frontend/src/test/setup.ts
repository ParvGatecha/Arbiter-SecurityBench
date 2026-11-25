import "@testing-library/jest-dom";

class ResizeObserverMock {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

if (typeof window !== "undefined" && !window.ResizeObserver) {
  window.ResizeObserver = ResizeObserverMock;
}

if (typeof window !== "undefined" && !window.URL.createObjectURL) {
  window.URL.createObjectURL = () => "blob:mock-url";
}

if (typeof window !== "undefined" && !window.URL.revokeObjectURL) {
  window.URL.revokeObjectURL = () => {};
}

if (typeof HTMLAnchorElement !== "undefined") {
  HTMLAnchorElement.prototype.click = () => {};
}
