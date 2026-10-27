import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Download, Trash2, Calendar, Clock, FileText, Shield } from 'lucide-react';
import { historyService } from '../services/historyService';
import { InvestigationDetail } from '../types';
import { ResultSummary } from '../components/ResultSummary';
import { EvidenceList } from '../components/EvidenceList';
import { ErrorMessage } from '../components/ErrorMessage';

export const ReportDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [exporting, setExporting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    historyService
      .getById(id)
      .then((data) => {
        setDetail(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Investigation not found.');
        setLoading(false);
      });
  }, [id]);

  const handleExportPdf = async () => {
    if (!id) return;
    setExporting(true);
    try {
      await historyService.exportPdf(id);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Export failed';
      alert(`PDF export failed: ${msg}`);
    } finally {
      setExporting(false);
    }
  };

  const handleDelete = async () => {
    if (!id) return;
    if (!window.confirm('Are you sure you want to delete this investigation report?')) {
      return;
    }
    try {
      await historyService.delete(id);
      navigate('/history');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Delete failed';
      alert(`Delete failed: ${msg}`);
    }
  };

  if (loading) {
    return (
      <div className="page-wrapper" style={{ textAlign: 'center', padding: '4rem' }}>
        <p style={{ color: 'var(--text-muted)' }}>Loading investigation record...</p>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="page-wrapper">
        <ErrorMessage message={error || 'Report not found.'} />
        <Link to="/history" className="btn-secondary" style={{ textDecoration: 'none' }}>
          <ArrowLeft size={16} />
          <span>Back to My investigations</span>
        </Link>
      </div>
    );
  }

  const result = detail.result_json;

  return (
    <div className="page-wrapper">
      {/* Top Action Nav */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <Link to="/history" className="btn-secondary" style={{ textDecoration: 'none' }}>
          <ArrowLeft size={16} />
          <span>Back to My investigations</span>
        </Link>

        <div style={{ display: 'flex', gap: '0.65rem' }}>
          <button
            type="button"
            className="btn-primary"
            onClick={handleExportPdf}
            disabled={exporting}
          >
            <Download size={16} />
            <span>{exporting ? 'Generating PDF...' : 'Download PDF Report'}</span>
          </button>
          <button
            type="button"
            onClick={handleDelete}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.65rem 1rem',
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#FCA5A5',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: 'var(--radius-sm)',
              fontWeight: 600,
              fontSize: '0.88rem',
              cursor: 'pointer',
            }}
          >
            <Trash2 size={16} />
            <span>Delete</span>
          </button>
        </div>
      </div>

      {/* Report Header Metadata */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)', fontSize: '0.82rem', marginBottom: '0.5rem' }}>
          <span>Investigation ID: <code>{detail.id}</code></span>
        </div>
        <h1 style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.75rem' }}>
          Forensic Report: {detail.input_display}
        </h1>
        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.86rem', color: 'var(--text-muted)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Calendar size={15} />
            {new Date(detail.created_at).toLocaleString()}
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <FileText size={15} />
            Module: <strong>{detail.type.toUpperCase()}</strong>
          </span>
          {detail.duration_ms !== undefined && detail.duration_ms !== null && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Clock size={15} />
              Latency: {detail.duration_ms} ms
            </span>
          )}
          {detail.model_version && (
            <span>Model: {detail.model_version}</span>
          )}
        </div>
      </div>

      {/* Result Summary (Verdict, explanation, actions, safety notice) */}
      {result && <ResultSummary result={result} />}

      {/* Forensic Evidence and Full Checks Detail */}
      {result && (
        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div style={{ paddingBottom: '0.75rem', borderBottom: '1px solid var(--border-light)', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)' }}>
              Full Technical Evidence & Verification Checks
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Comprehensive forensic indicators, detection rules, and engine verification checks
            </p>
          </div>

          <EvidenceList
            evidence={result.evidence || []}
            checks={result.checks_performed || []}
            limitations={result.limitations || []}
          />
        </div>
      )}
    </div>
  );
};
