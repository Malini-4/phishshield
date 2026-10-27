import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Smartphone,
  MessageSquare,
  Receipt,
  ArrowRight,
  Shield,
  Search,
} from 'lucide-react';
import { historyService } from '../services/historyService';
import { DashboardStats } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorMessage } from '../components/ErrorMessage';
import { useAuth } from '../context/AuthContext';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    historyService
      .getStats()
      .then((statsData) => {
        setStats(statsData);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load investigation data.');
        setLoading(false);
      });
  }, []);

  const modules = [
    {
      title: 'URL Threat Analysis',
      desc: 'Analyze suspicious links for phishing indicators, deceptive subdomains, typosquatting, and malicious hosting.',
      icon: Globe,
      to: '/url',
      count: stats?.by_type?.url || 0,
      color: '#0284C7', // Sky-600
    },
    {
      title: 'Android APK Analysis',
      desc: 'Static application security inspection: inspect manifest declarations, critical permissions, and DEX strings without execution.',
      icon: Smartphone,
      to: '/apk',
      count: stats?.by_type?.apk || 0,
      color: '#0369A1', // Sky-700
    },
    {
      title: 'SMS Scam Verification',
      desc: 'Verify Indian sender headers against TRAI DLT registrations and inspect message text for urgent banking or KYC fraud.',
      icon: MessageSquare,
      to: '/sms',
      count: stats?.by_type?.sms || 0,
      color: '#0F766E', // Teal-700
    },
    {
      title: 'Payment Screenshot Analysis',
      desc: 'Optical character recognition (OCR) and inconsistency engine to verify claimed UPI amounts, transaction IDs, and receipt status.',
      icon: Receipt,
      to: '/screenshot',
      count: stats?.by_type?.screenshot || 0,
      color: '#D97706', // Amber-600
    },
  ];

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">
          {user ? `Welcome, ${user.full_name}` : 'PhishShield Security Operations'}
        </h1>
        <p className="page-subtitle">
          Evidence-based digital forensics dashboard for phishing links, malicious APKs, SMS fraud, and manipulated payment receipts.
        </p>
      </div>

      {error && <ErrorMessage message={error} />}

      {/* Investigation Modules Grid */}
      <div style={{ marginBottom: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)' }}>
            Investigation Modules
          </h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-subtle)' }}>
            Total Investigations: <strong>{stats?.total ?? 0}</strong>
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
          {modules.map((m) => {
            const Icon = m.icon;
            return (
              <div
                key={m.to}
                className="card"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  marginBottom: 0,
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
                    <div
                      style={{
                        width: '42px',
                        height: '42px',
                        borderRadius: '10px',
                        background: `${m.color}15`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Icon size={22} color={m.color} />
                    </div>
                    <span
                      style={{
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        background: 'var(--primary-subtle)',
                        color: 'var(--primary)',
                        padding: '0.25rem 0.65rem',
                        borderRadius: '12px',
                        border: '1px solid var(--primary-border)',
                      }}
                    >
                      {m.count} {m.count === 1 ? 'Scan' : 'Scans'}
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.4rem', color: 'var(--text-main)' }}>
                    {m.title}
                  </h3>
                  <p style={{ fontSize: '0.86rem', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: '1.25rem' }}>
                    {m.desc}
                  </p>
                </div>

                <Link
                  to={m.to}
                  className="btn-primary"
                  style={{ width: '100%', justifyContent: 'space-between', textDecoration: 'none' }}
                >
                  <span>Launch Investigation</span>
                  <ArrowRight size={15} />
                </Link>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Investigations Feed */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)' }}>
              Recent Investigations
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Investigations recorded in your personal database
            </p>
          </div>
          <Link to="/history" className="btn-secondary" style={{ fontSize: '0.85rem', textDecoration: 'none' }}>
            <span>View My investigations</span>
            <ArrowRight size={14} />
          </Link>
        </div>

        {loading ? (
          <p style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading your investigation history...
          </p>
        ) : !stats || stats.recent.length === 0 ? (
          <EmptyState
            title="No Investigations Yet"
            description="Your investigation database is currently empty. Start by scanning a suspicious URL, uploading an APK, or analyzing an SMS."
            actionText="Analyze a URL"
            onAction={() => window.location.assign('/url')}
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {stats.recent.map((item) => (
              <Link
                key={item.id}
                to={`/history/${item.id}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.85rem 1rem',
                  border: '1px solid var(--border-light)',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(4, 15, 38, 0.7)',
                  textDecoration: 'none',
                  color: 'inherit',
                  transition: 'border-color 0.15s ease, background 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', minWidth: 0 }}>
                  <span
                    style={{
                      textTransform: 'uppercase',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      background: 'var(--primary-subtle)',
                      color: 'var(--primary)',
                      border: '1px solid var(--primary-border)',
                      flexShrink: 0,
                    }}
                  >
                    {item.type}
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.input_display}
                    </p>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-subtle)' }}>
                      {new Date(item.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div style={{ flexShrink: 0, marginLeft: '0.75rem' }}>
                  <StatusBadge verdict={item.verdict} label={item.display_label} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
