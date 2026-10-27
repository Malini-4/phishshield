import React from 'react';
import { Loader2 } from 'lucide-react';

interface ScanProgressProps {
  message?: string;
  step?: string;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  message = 'Performing deep multi-layer security analysis...',
  step,
}) => {
  return (
    <div
      className="card"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 2rem',
        textAlign: 'center',
      }}
      aria-live="polite"
    >
      <Loader2
        size={36}
        className="animate-spin"
        style={{ color: 'var(--primary)', marginBottom: '1rem', animation: 'spin 1s linear infinite' }}
      />
      <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.4rem' }}>
        {message}
      </h3>
      {step && (
        <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)' }}>
          {step}
        </p>
      )}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
