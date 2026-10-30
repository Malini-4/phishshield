import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FolderOpen, ShieldAlert, AlertTriangle, CheckCircle2, ShieldQuestion, ArrowRight, Shield, Layers, Calendar, Clock } from 'lucide-react';
import { caseService } from '../services/caseService';
import { CaseSummary, Verdict } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorMessage } from '../components/ErrorMessage';

export const CasesPage: React.FC = () => {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCases = () => {
    setLoading(true);
    setError(null);
    caseService
      .listCases()
      .then((data) => {
        setCases(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load cases.');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const getRiskIcon = (risk: Verdict) => {
    switch (risk) {
      case 'malicious':
        return <ShieldAlert size={20} color="#EF4444" />;
      case 'suspicious':
        return <AlertTriangle size={20} color="#F59E0B" />;
      case 'clean_no_findings':
        return <CheckCircle2 size={20} color="#10B981" />;
      default:
        return <ShieldQuestion size={20} color="#94A3B8" />;
    }
  };

  return (
    <div className="page-wrapper">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <FolderOpen size={28} color="#16C8FF" />
            <span>Connected Cases</span>
          </h1>
          <p className="page-subtitle">
            Cryptographically linked case dossiers grouping related threats, shared clues, and cross-investigation evidence.
          </p>
        </div>
      </div>

      {error && <ErrorMessage message={error} onRetry={fetchCases} />}

      {loading ? (
        <div className="card" style={{ padding: '3.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <p>Loading active case dossiers...</p>
        </div>
      ) : cases.length === 0 ? (
        <div className="card" style={{ padding: '2.5rem' }}>
          <EmptyState
            title="No Connected Cases Found"
            description="Cases are opened automatically when shared indicators (such as identical UPI IDs, phone numbers, or suspicious links) connect multiple investigations together."
            actionText="Start New Analysis"
            onAction={() => { window.location.href = '/'; }}
          />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {cases.map((c) => (
            <Link
              key={c.id}
              to={`/cases/${c.id}`}
              style={{ textDecoration: 'none' }}
            >
              <div
                className="card"
                style={{
                  padding: '1.25rem 1.5rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1.25rem',
                  flexWrap: 'wrap',
                  transition: 'all 0.2s ease',
                  border: '1px solid var(--border-light)',
                  cursor: 'pointer',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'var(--cyber-cyan)';
                  e.currentTarget.style.boxShadow = '0 4px 20px rgba(8, 127, 245, 0.2)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = 'var(--border-light)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', flex: 1, minWidth: '280px' }}>
                  <div
                    style={{
                      width: '42px',
                      height: '42px',
                      borderRadius: '10px',
                      background: 'rgba(8, 127, 245, 0.15)',
                      border: '1px solid rgba(22, 200, 255, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    {getRiskIcon(c.risk_level)}
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem', flexWrap: 'wrap' }}>
                      <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
                        {c.title}
                      </h3>
                      <StatusBadge verdict={c.risk_level} label={c.risk_level.replace('_', ' ').toUpperCase()} />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', fontSize: '0.82rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <Layers size={14} color="#16C8FF" />
                        <span>{c.evidence_count} evidence item{c.evidence_count === 1 ? '' : 's'}</span>
                      </span>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <Clock size={14} />
                        <span>Updated {new Date(c.updated_at).toLocaleString()}</span>
                      </span>
                      {c.modules && c.modules.length > 0 && (
                        <div style={{ display: 'flex', gap: '0.35rem' }}>
                          {c.modules.map((m) => (
                            <span
                              key={m}
                              style={{
                                padding: '0.15rem 0.5rem',
                                borderRadius: '4px',
                                background: 'rgba(22, 200, 255, 0.12)',
                                border: '1px solid rgba(22, 200, 255, 0.25)',
                                color: '#16C8FF',
                                fontSize: '0.72rem',
                                fontWeight: 600,
                                textTransform: 'uppercase',
                              }}
                            >
                              {m}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#16C8FF', fontWeight: 600, fontSize: '0.88rem' }}>
                  <span>View Case</span>
                  <ArrowRight size={16} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};
