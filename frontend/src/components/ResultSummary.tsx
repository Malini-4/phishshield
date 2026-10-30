import React from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ShieldQuestion,
  ExternalLink,
  ShieldCheck,
  Info,
  FolderOpen,
} from 'lucide-react';
import { AnalysisResult } from '../types';
import { StatusBadge } from './StatusBadge';
import { Link } from 'react-router-dom';

interface ResultSummaryProps {
  result: AnalysisResult;
}

export const ResultSummary: React.FC<ResultSummaryProps> = ({ result }) => {
  const getVerdictClass = (v: string) => {
    switch (v) {
      case 'malicious':
        return 'malicious';
      case 'suspicious':
        return 'suspicious';
      case 'clean_no_findings':
        return 'clean';
      case 'inconclusive':
      default:
        return 'inconclusive';
    }
  };

  const getVerdictIcon = (v: string) => {
    switch (v) {
      case 'malicious':
        return <ShieldAlert size={32} color="#DC2626" />;
      case 'suspicious':
        return <AlertTriangle size={32} color="#D97706" />;
      case 'clean_no_findings':
        return <CheckCircle2 size={32} color="#0F766E" />;
      case 'inconclusive':
      default:
        return <ShieldQuestion size={32} color="#64748B" />;
    }
  };

  const getSafetyNoticeText = () => {
    switch (result.verdict) {
      case 'clean_no_findings':
        return 'No known threat indicators were detected during automated checks. However, this is not an absolute guarantee of safety. Zero-day threats or newly hosted malicious payloads may not yet appear in security databases. Always verify unexpected notifications directly with your official service provider.';
      case 'malicious':
        return 'Critical threat indicators were detected. Do not click links, submit personal credentials, install software, or send payments. If you suspect fraud, document the details and report to https://cybercrime.gov.in or Helpline 1930.';
      case 'suspicious':
        return 'Unusual patterns or potential impersonation markers were detected. Exercise extreme caution. Do not disclose OTPs, banking PINs, or sensitive information until verified through independent, official channels.';
      case 'inconclusive':
      default:
        return 'Important details could not be fully evaluated due to insufficient data or ambiguous content. Treat unverified requests with caution and confirm directly with the originating institution.';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Connected Case Banner */}
      {result.case_id && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.85rem 1.25rem',
            background: 'rgba(8, 127, 245, 0.12)',
            border: '1px solid rgba(22, 200, 255, 0.35)',
            borderRadius: 'var(--radius-md)',
            color: '#EAF5FF',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <FolderOpen size={20} color="#16C8FF" />
            <div>
              <span style={{ fontSize: '0.92rem', fontWeight: 700, color: '#FFFFFF' }}>
                This is part of an active Case dossier
              </span>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
                Automatically grouped with other investigations sharing common threat indicators.
              </p>
            </div>
          </div>
          <Link
            to={`/cases/${result.case_id}`}
            className="btn-secondary"
            style={{
              fontSize: '0.82rem',
              padding: '0.45rem 0.95rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              textDecoration: 'none',
              fontWeight: 600,
              border: '1px solid rgba(22, 200, 255, 0.4)',
            }}
          >
            <span>View Case</span>
            <ExternalLink size={14} />
          </Link>
        </div>
      )}

      {/* 1. Main Verdict & Short Explanation Card */}
      <div className={`card result-header-card ${getVerdictClass(result.verdict)}`}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', flex: 1, minWidth: '280px' }}>
            <div style={{ flexShrink: 0, marginTop: '0.15rem' }}>
              {getVerdictIcon(result.verdict)}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem', flexWrap: 'wrap' }}>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {result.display_label}
                </h3>
                <StatusBadge verdict={result.verdict} label={result.verdict.replace('_', ' ').toUpperCase()} />
              </div>
              <p style={{ fontSize: '0.98rem', color: 'var(--text-main)', lineHeight: 1.5, fontWeight: 500 }}>
                {result.summary}
              </p>
            </div>
          </div>

          {/* 5. View Full Report CTA */}
          <Link
            to={`/history/${result.investigation_id}`}
            className="btn-primary"
            style={{ fontSize: '0.88rem', padding: '0.55rem 1.1rem', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <span>View Full Report</span>
            <ExternalLink size={15} />
          </Link>
        </div>
      </div>

      {/* 3. Recommended Actions Card */}
      {result.recommendations.length > 0 && (
        <div className="card">
          <h4 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--text-main)' }}>
            Recommended Action
          </h4>
          <ul style={{ paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.92rem', color: 'var(--text-muted)' }}>
            {result.recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 4. Safety Notice Card */}
      <div
        className="card"
        style={{
          borderLeft: '4px solid var(--primary)',
          background: 'var(--bg-card)',
          padding: '1rem 1.25rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
          <Info size={20} color="var(--primary)" style={{ flexShrink: 0, marginTop: '0.15rem' }} />
          <div>
            <h5 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.25rem' }}>
              Safety Notice
            </h5>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              {getSafetyNoticeText()}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
