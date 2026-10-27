import React, { useEffect, useState } from 'react';
import { Menu, ShieldCheck, AlertCircle } from 'lucide-react';
import { historyService } from '../services/historyService';
import { HealthStatus } from '../types';

interface TopbarProps {
  onToggleSidebar: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onToggleSidebar }) => {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    historyService
      .getHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  return (
    <header className="topbar">
      <button
        type="button"
        onClick={onToggleSidebar}
        style={{
          display: 'none',
          background: 'none',
          border: 'none',
          padding: '0.5rem',
          cursor: 'pointer',
        }}
        className="mobile-menu-btn"
        aria-label="Toggle menu"
      >
        <Menu size={22} />
      </button>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)' }}>
          Digital Evidence & Scam Defense
        </h2>
      </div>

      <div className="system-status">
        {health ? (
          <>
            <span
              className={`status-dot ${health.status === 'ok' ? '' : 'degraded'}`}
              aria-hidden="true"
            />
            <span>
              Engine: <strong>Online</strong>
              {health.model_loaded && ' • URL Model: Loaded'}
              {health.ocr_available && ' • OCR: Ready'}
            </span>
          </>
        ) : (
          <>
            <span className="status-dot degraded" aria-hidden="true" />
            <span style={{ color: 'var(--text-muted)' }}>Backend: Checking...</span>
          </>
        )}
      </div>

      <style>{`
        @media (max-width: 768px) {
          .mobile-menu-btn {
            display: block !important;
          }
        }
      `}</style>
    </header>
  );
};
