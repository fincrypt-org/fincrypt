import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

// ErrorBoundary catches render-time errors and shows a recovery UI
// instead of a blank page.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error): void {
    // No telemetry in v1 — errors stay on-device.
    console.error('unhandled UI error', error)
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <main role="alert" style={{ padding: '2rem', fontFamily: 'system-ui' }}>
          <h1>Something went wrong</h1>
          <p>The error has been logged locally. Reload to continue.</p>
        </main>
      )
    }
    return this.props.children
  }
}
