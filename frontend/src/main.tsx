import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import MockApp from './MockApp'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    {new URLSearchParams(window.location.search).has('mock') ? <MockApp /> : <App />}
  </React.StrictMode>,
)
