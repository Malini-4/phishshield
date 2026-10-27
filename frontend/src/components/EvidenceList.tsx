import React from 'react';
import { AlertCircle, Check, Info, Minus, X } from 'lucide-react';
import { CheckPerformed, EvidenceItem } from '../types';

interface EvidenceListProps {
  evidence: EvidenceItem[];
  checks: CheckPerformed[];
  limitations: string[];
}

export const EvidenceList: React.FC<EvidenceListProps> = ({
  evidence,
  checks,
  limitations,
}) => {
  const getSeverityBadge = (severity: string) => {
    const colors: Record<string, { bg: string; text: string }> = {
      high: { bg: 'rgba(239, 68, 68, 0.2)', text: '#FCA5A5' },
      medium: { bg: 'rgba(245, 158, 11, 0.2)', text: '#FCD34D' },
      low: { bg: 'rgba(8, 127, 245, 0.25)', text: '#70D8FF' },
      info: { bg: 'rgba(148, 163, 184, 0.2)', text: '#CBD5E1' },
    };
    const c = colors[severity] || colors.info;
    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.15rem 0.5rem',
          borderRadius: '4px',
          fontSize: '0.75rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          background: c.bg,
          color: c.text,
        }}
      >
        {severity}
      </span>
    );
  };

  const getCheckStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <Check size={16} color="#10B981" aria-label="Completed" />;
      case 'failed':
        return <X size={16} color="#DC2626" aria-label="Failed" />;
      case 'unavailable':
        return <Minus size={16} color="#94A3B8" aria-label="Unavailable" />;
      case 'skipped':
      default:
        return <Minus size={16} color="#CBD5E1" aria-label="Skipped" />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1rem' }}>
      {/* Evidence Findings */}
      <div>
        <h4 style={{ fontSize: '0.98rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-main)' }}>
          Detailed Evidence Findings ({evidence.length})
        </h4>
        {evidence.length === 0 ? (
          <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            No suspicious indicators were triggered by the rules or models.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {evidence.map((item) => (
              <div
                key={item.id}
                style={{
                  border: '1px solid var(--border-light)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  background: 'rgba(4, 15, 38, 0.7)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {getSeverityBadge(item.severity)}
                    <span style={{ fontWeight: 600, fontSize: '0.92rem' }}>{item.title}</span>
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-subtle)' }}>
                    Source: {item.source}
                  </span>
                </div>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                  {item.detail}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Checks Performed */}
      <div>
        <h4 style={{ fontSize: '0.98rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-main)' }}>
          Security Verification Checks ({checks.length})
        </h4>
        <div style={{ border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
          {checks.map((chk, idx) => (
            <div
              key={chk.name + idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.65rem 1rem',
                borderBottom: idx < checks.length - 1 ? '1px solid var(--border-light)' : 'none',
                background: idx % 2 === 0 ? 'rgba(4, 15, 38, 0.7)' : 'rgba(7, 24, 60, 0.5)',
                fontSize: '0.88rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                {getCheckStatusIcon(chk.status)}
                <span style={{ fontWeight: 500 }}>{chk.name}</span>
              </div>
              <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                {chk.detail || chk.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Honest Limitations */}
      {limitations.length > 0 && (
        <div style={{ padding: '0.85rem 1rem', background: 'rgba(4, 15, 38, 0.7)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.4rem', color: 'var(--text-muted)' }}>
            <Info size={16} />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Known Limitations & Caveats</span>
          </div>
          <ul style={{ paddingLeft: '1.25rem', fontSize: '0.82rem', color: 'var(--text-subtle)', lineHeight: 1.4 }}>
            {limitations.map((lim, i) => (
              <li key={i}>{lim}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
