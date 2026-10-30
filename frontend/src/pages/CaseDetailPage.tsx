import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FolderOpen,
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  FileText,
  FileCode,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Plus,
  Send,
  Layers,
  Link2,
  Hash,
  Clock,
  Shield,
  MessageSquare,
  Globe,
  Smartphone,
  Receipt,
} from 'lucide-react';
import { caseService } from '../services/caseService';
import { CaseDetail, CaseVerificationResult, Verdict } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { ErrorMessage } from '../components/ErrorMessage';

export const CaseDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [caseData, setCaseData] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Verification state
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verification, setVerification] = useState<CaseVerificationResult | null>(null);

  // Note input state
  const [noteText, setNoteText] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);

  // Graph hover state
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const fetchCase = () => {
    if (!id) return;
    setLoading(true);
    caseService
      .getCase(id)
      .then((data) => {
        setCaseData(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to fetch case details.');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchCase();
  }, [id]);

  const handleVerify = async () => {
    if (!id) return;
    setVerifying(true);
    try {
      const res = await caseService.verifyCase(id);
      setVerification(res);
    } catch (err: any) {
      alert(`Verification failed: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!id) return;
    try {
      await caseService.downloadPdf(id);
    } catch (err: any) {
      alert(`Failed to download PDF export: ${err.message}`);
    }
  };

  const handleDownloadJson = async () => {
    if (!id) return;
    try {
      await caseService.downloadJson(id);
    } catch (err: any) {
      alert(`Failed to download JSON export: ${err.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id || !noteText.trim()) return;

    setSubmittingNote(true);
    try {
      await caseService.addNote(id, noteText.trim());
      setNoteText('');
      fetchCase(); // Refresh to include new note in ledger
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setSubmittingNote(false);
    }
  };

  const getModuleIcon = (mod: string) => {
    switch (mod.toLowerCase()) {
      case 'url':
        return <Globe size={16} color="#16C8FF" />;
      case 'sms':
        return <MessageSquare size={16} color="#10B981" />;
      case 'apk':
        return <Smartphone size={16} color="#8B5CF6" />;
      case 'screenshot':
        return <Receipt size={16} color="#F59E0B" />;
      default:
        return <Layers size={16} color="#64748B" />;
    }
  };

  if (loading) {
    return (
      <div className="page-wrapper">
        <div className="card" style={{ padding: '4rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <p>Loading case evidence and cryptographic ledger...</p>
        </div>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="page-wrapper">
        <ErrorMessage message={error || 'Case not found.'} onRetry={fetchCase} />
        <Link to="/cases" className="btn-secondary" style={{ marginTop: '1rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
          <ArrowLeft size={16} />
          <span>Back to Cases</span>
        </Link>
      </div>
    );
  }

  // Pre-calculate circular coordinates for Graph
  const svgWidth = 720;
  const svgHeight = 440;
  const cx = svgWidth / 2;
  const cy = svgHeight / 2;

  const evidenceNodes = caseData.graph.nodes.filter((n) => n.type === 'evidence');
  const clueNodes = caseData.graph.nodes.filter((n) => n.type === 'clue');

  const nodePositions: Record<string, { x: number; y: number }> = {};

  // Outer circle for Evidence
  const rEvidence = 160;
  evidenceNodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / (evidenceNodes.length || 1) - Math.PI / 2;
    nodePositions[node.id] = {
      x: cx + rEvidence * Math.cos(angle),
      y: cy + rEvidence * Math.sin(angle),
    };
  });

  // Inner circle for Clues
  const rClues = 85;
  clueNodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / (clueNodes.length || 1) + Math.PI / 4;
    nodePositions[node.id] = {
      x: cx + rClues * Math.cos(angle),
      y: cy + rClues * Math.sin(angle),
    };
  });

  return (
    <div className="page-wrapper">
      {/* Back button */}
      <div style={{ marginBottom: '1rem' }}>
        <Link
          to="/cases"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            color: '#16C8FF',
            fontSize: '0.88rem',
            textDecoration: 'none',
            fontWeight: 600,
          }}
        >
          <ArrowLeft size={16} />
          <span>Back to All Cases</span>
        </Link>
      </div>

      {/* Case Header Card */}
      <div className="card" style={{ padding: '1.5rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem', flexWrap: 'wrap' }}>
              <span
                style={{
                  padding: '0.2rem 0.55rem',
                  borderRadius: '4px',
                  background: 'rgba(22, 200, 255, 0.15)',
                  border: '1px solid rgba(22, 200, 255, 0.35)',
                  color: '#16C8FF',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                }}
              >
                Case Dossier
              </span>
              <StatusBadge verdict={caseData.risk_level} label={caseData.risk_level.replace('_', ' ').toUpperCase()} />
              <span style={{ fontSize: '0.82rem', color: 'var(--text-subtle)' }}>
                Status: <strong style={{ color: '#10B981' }}>{caseData.status.toUpperCase()}</strong>
              </span>
            </div>

            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#FFFFFF', margin: '0 0 0.5rem 0' }}>
              {caseData.title}
            </h1>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', fontSize: '0.82rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
              <span>Case ID: <code style={{ color: '#EAF5FF' }}>{caseData.id}</code></span>
              <span>Opened: {new Date(caseData.created_at).toLocaleString()}</span>
              <span>Updated: {new Date(caseData.updated_at).toLocaleString()}</span>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
            <button
              onClick={handleVerify}
              disabled={verifying}
              className="btn-secondary"
              style={{
                fontSize: '0.85rem',
                padding: '0.5rem 0.9rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                border: '1px solid rgba(22, 200, 255, 0.4)',
              }}
            >
              <ShieldCheck size={16} color="#16C8FF" />
              <span>{verifying ? 'Verifying...' : 'Verify Integrity'}</span>
            </button>

            <button
              onClick={handleDownloadPdf}
              className="btn-secondary"
              style={{
                fontSize: '0.85rem',
                padding: '0.5rem 0.9rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
              }}
            >
              <FileText size={16} />
              <span>Export PDF</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="btn-secondary"
              style={{
                fontSize: '0.85rem',
                padding: '0.5rem 0.9rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
              }}
            >
              <FileCode size={16} />
              <span>Export JSON</span>
            </button>
          </div>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div
          style={{
            marginBottom: '1.25rem',
            padding: '1rem 1.25rem',
            borderRadius: 'var(--radius-md)',
            background: verification.status === 'intact' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${verification.status === 'intact' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.5)'}`,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.85rem',
          }}
        >
          {verification.status === 'intact' ? (
            <CheckCircle2 size={24} color="#10B981" style={{ flexShrink: 0, marginTop: '2px' }} />
          ) : (
            <XCircle size={24} color="#EF4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          )}
          <div style={{ flex: 1 }}>
            <h4 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 0.25rem 0', color: verification.status === 'intact' ? '#10B981' : '#EF4444' }}>
              {verification.status === 'intact'
                ? 'Cryptographic Ledger Integrity Verified (Intact)'
                : 'Ledger Tamper Alert! Integrity Check Failed'}
            </h4>
            <p style={{ fontSize: '0.85rem', color: '#EAF5FF', margin: 0, lineHeight: 1.45 }}>
              {verification.status === 'intact'
                ? `All ${caseData.members.length} evidence records and ledger event hashes are cryptographically intact under Section 63 Bharatiya Sakshya Adhiniyam 2023. Head Hash: ${verification.head_hash?.slice(0, 16)}...`
                : `Tampering detected: ${verification.problems.join(', ')}`}
            </p>
          </div>
        </div>
      )}

      {/* Circular Interactive Threat Correlation Graph */}
      <div className="card" style={{ padding: '1.25rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>
              Threat Correlation Graph
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
              Visualizing how evidence modules are interlinked through shared indicators (UPI IDs, phone numbers, domains).
            </p>
          </div>
          <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#EF4444', display: 'inline-block' }} />
              <span>Evidence</span>
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: '#00F0FF', display: 'inline-block' }} />
              <span>Shared Clue (≥2 links)</span>
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: '#94A3B8', display: 'inline-block' }} />
              <span>Clue</span>
            </span>
          </div>
        </div>

        <div style={{ overflowX: 'auto', textAlign: 'center', background: 'rgba(3, 11, 28, 0.7)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
          <svg width={svgWidth} height={svgHeight} style={{ maxWidth: '100%', height: 'auto' }}>
            {/* Background circular guide tracks */}
            <circle cx={cx} cy={cy} r={rEvidence} fill="none" stroke="rgba(22, 200, 255, 0.08)" strokeDasharray="4 4" />
            <circle cx={cx} cy={cy} r={rClues} fill="none" stroke="rgba(22, 200, 255, 0.08)" strokeDasharray="4 4" />

            {/* Connecting Edges */}
            {caseData.graph.edges.map((edge, i) => {
              const p1 = nodePositions[edge.source];
              const p2 = nodePositions[edge.target];
              if (!p1 || !p2) return null;
              const isHighlighted = hoveredNode && (hoveredNode === edge.source || hoveredNode === edge.target);

              return (
                <line
                  key={`edge_${i}`}
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={isHighlighted ? '#00F0FF' : 'rgba(22, 200, 255, 0.25)'}
                  strokeWidth={isHighlighted ? 2.5 : 1.2}
                  strokeOpacity={hoveredNode ? (isHighlighted ? 1 : 0.2) : 0.7}
                  style={{ transition: 'all 0.2s ease' }}
                />
              );
            })}

            {/* Nodes */}
            {caseData.graph.nodes.map((node) => {
              const pos = nodePositions[node.id];
              if (!pos) return null;
              const isEvidence = node.type === 'evidence';
              const isShared = node.is_shared;
              const isHovered = hoveredNode === node.id;

              const getNodeColor = () => {
                if (isEvidence) {
                  if (node.verdict === 'malicious') return '#EF4444';
                  if (node.verdict === 'suspicious') return '#F59E0B';
                  if (node.verdict === 'clean_no_findings') return '#10B981';
                  return '#64748B';
                }
                return isShared ? '#00F0FF' : '#94A3B8';
              };

              const color = getNodeColor();

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  style={{ cursor: 'pointer' }}
                >
                  {isEvidence ? (
                    <circle
                      r={isHovered ? 20 : 16}
                      fill="rgba(6, 22, 54, 0.9)"
                      stroke={color}
                      strokeWidth={isHovered ? 3 : 2}
                      style={{ transition: 'all 0.2s ease' }}
                    />
                  ) : (
                    <rect
                      x={isHovered ? -14 : -11}
                      y={isHovered ? -14 : -11}
                      width={isHovered ? 28 : 22}
                      height={isHovered ? 28 : 22}
                      rx={4}
                      fill="rgba(6, 22, 54, 0.9)"
                      stroke={color}
                      strokeWidth={isShared ? (isHovered ? 3 : 2.2) : 1.5}
                      style={{ transition: 'all 0.2s ease' }}
                    />
                  )}

                  {/* Label */}
                  <text
                    y={isEvidence ? 26 : 22}
                    textAnchor="middle"
                    fill={isHovered ? '#FFFFFF' : '#BFDCFC'}
                    fontSize={isHovered ? '11px' : '9.5px'}
                    fontWeight={isHovered || isShared ? 700 : 500}
                    style={{ pointerEvents: 'none', userSelect: 'none' }}
                  >
                    {node.label.length > 22 ? `${node.label.slice(0, 20)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      {/* Grid: Evidence List & Shared Clues */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.25rem', marginBottom: '1.25rem' }}>
        {/* Evidence Members */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={18} color="#16C8FF" />
            <span>Case Evidence ({caseData.members.length})</span>
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {caseData.members.map((m) => (
              <div
                key={m.investigation_id}
                style={{
                  padding: '0.85rem 1rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(3, 11, 28, 0.6)',
                  border: '1px solid var(--border-light)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '0.75rem',
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    {getModuleIcon(m.type)}
                    <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#16C8FF', textTransform: 'uppercase' }}>
                      {m.type}
                    </span>
                    <StatusBadge verdict={m.verdict} label={m.verdict.replace('_', ' ').toUpperCase()} />
                  </div>
                  <p style={{ fontSize: '0.85rem', color: '#EAF5FF', margin: '0 0 0.35rem 0', wordBreak: 'break-word', fontWeight: 500 }}>
                    {m.summary}
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-subtle)' }}>
                    <span>SHA-256: <code style={{ color: '#16C8FF' }}>{m.result_hash.slice(0, 10)}...</code></span>
                    <span>{new Date(m.added_at).toLocaleDateString()}</span>
                  </div>
                </div>

                <Link
                  to={`/history/${m.investigation_id}`}
                  style={{
                    color: '#16C8FF',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.35rem',
                    borderRadius: '4px',
                    background: 'rgba(22, 200, 255, 0.1)',
                  }}
                  title="View Investigation Report"
                >
                  <ExternalLink size={15} />
                </Link>
              </div>
            ))}
          </div>
        </div>

        {/* Shared Clues & Clue Registry */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Link2 size={18} color="#00F0FF" />
            <span>Extracted Clues ({caseData.clues.length})</span>
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {caseData.clues.map((clue, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  background: clue.is_shared ? 'rgba(0, 240, 255, 0.08)' : 'rgba(3, 11, 28, 0.5)',
                  border: clue.is_shared ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid var(--border-light)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '0.5rem',
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.15rem' }}>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-subtle)', textTransform: 'uppercase' }}>
                      {clue.entity_type}
                    </span>
                    {clue.is_shared && (
                      <span
                        style={{
                          padding: '0.1rem 0.4rem',
                          borderRadius: '3px',
                          background: '#00F0FF',
                          color: '#041438',
                          fontSize: '0.68rem',
                          fontWeight: 700,
                        }}
                      >
                        Shared Link ({clue.count})
                      </span>
                    )}
                  </div>
                  <p style={{ fontSize: '0.85rem', color: '#FFFFFF', margin: 0, wordBreak: 'break-all', fontFamily: 'monospace' }}>
                    {clue.entity_value}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Cryptographic Event Ledger */}
      <div className="card" style={{ padding: '1.25rem', marginBottom: '1.25rem', overflow: 'hidden' }}>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Hash size={18} color="#16C8FF" />
          <span>Tamper-Evident Cryptographic Ledger</span>
        </h3>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Every case action is cryptographically hashed with SHA-256 and chained to previous events for legal admissibility under Section 63 BSA 2023.
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
            <thead>
              <tr style={{ background: 'rgba(8, 26, 64, 0.95)', borderBottom: '1px solid var(--border-light)', color: '#EAF5FF' }}>
                <th style={{ padding: '0.65rem 0.85rem' }}>Seq</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Event Type</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Prev Hash</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Record Hash</th>
              </tr>
            </thead>
            <tbody>
              {caseData.ledger.map((ev) => (
                <tr key={ev.seq} style={{ borderBottom: '1px solid var(--border-dark)' }}>
                  <td style={{ padding: '0.65rem 0.85rem', fontWeight: 700, color: '#16C8FF' }}>
                    #{ev.seq}
                  </td>
                  <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-muted)' }}>
                    {new Date(ev.ts).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '0.65rem 0.85rem' }}>
                    <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(22, 200, 255, 0.1)', color: '#EAF5FF', fontWeight: 600 }}>
                      {ev.event_type}
                    </span>
                  </td>
                  <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'monospace', color: 'var(--text-subtle)' }}>
                    {ev.prev_hash.slice(0, 12)}...
                  </td>
                  <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'monospace', color: '#10B981', fontWeight: 600 }}>
                    {ev.record_hash.slice(0, 12)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Case Notes & Investigator Observations */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#FFFFFF', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileText size={18} color="#16C8FF" />
          <span>Investigator Notes ({caseData.notes.length})</span>
        </h3>

        {/* Existing Notes */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.25rem' }}>
          {caseData.notes.length === 0 ? (
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: 0 }}>
              No notes logged yet. Add your first observation below to record it in the ledger.
            </p>
          ) : (
            caseData.notes.map((note, i) => (
              <div
                key={i}
                style={{
                  padding: '0.85rem 1rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(3, 11, 28, 0.6)',
                  border: '1px solid var(--border-light)',
                }}
              >
                <p style={{ fontSize: '0.9rem', color: '#FFFFFF', margin: '0 0 0.35rem 0', lineHeight: 1.45 }}>
                  {note.text}
                </p>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-subtle)' }}>
                  Ledger #{note.seq} • Logged at {new Date(note.added_at).toLocaleString()}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Add Note Form */}
        <form onSubmit={handleAddNote} style={{ display: 'flex', gap: '0.65rem' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Add an investigator observation or legal note..."
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            disabled={submittingNote}
            style={{ flex: 1 }}
          />
          <button
            type="submit"
            className="btn-primary"
            disabled={submittingNote || !noteText.trim()}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.55rem 1.1rem' }}
          >
            <Send size={15} />
            <span>Add Note</span>
          </button>
        </form>
      </div>
    </div>
  );
};
