import { useEffect } from 'react';
import { Navigate } from 'react-router-dom';

const BACKEND_DASHBOARD_URL = import.meta.env.VITE_BACKEND_DASHBOARD_URL || 'http://localhost:5000/dashboard';

export default function Dashboard() {
  const token = window.localStorage.getItem('deepsentinelToken');

  useEffect(() => {
    if (token) {
      window.location.href = BACKEND_DASHBOARD_URL;
    }
  }, [token]);

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return null;
}
