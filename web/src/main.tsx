import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { ErrorBoundary } from './components/ErrorBoundary'

// bootstrap mounts the app inside StrictMode with routing.
function bootstrap(): void {
  const rootEl = document.getElementById('root')
  if (!rootEl) throw new Error('missing #root element')
  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <BrowserRouter>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </BrowserRouter>
    </React.StrictMode>,
  )
}

bootstrap()
