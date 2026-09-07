import { Route, Routes } from 'react-router-dom'
import Home from './pages/Home'
import Login from './pages/Login'
import Register from './pages/Register'
import DevCrypto from './pages/DevCrypto'

// App maps routes to placeholder pages (real flows arrive in P1/P2).
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/dev/crypto" element={<DevCrypto />} />
    </Routes>
  )
}
