import React, { useState, useRef } from 'react';
import { UploadCloud, FileCode, AlertTriangle, ArrowRight, X, Lock, LogIn } from 'lucide-react';
import { validatePcapFile } from '../utils/validation';
import { formatBytes } from '../utils/formatters';
import { useAuth } from '../context/AuthContext';

export default function UploadForm({ onUpload, uploading = false }) {
  const { isAuthenticated, openAuthModal } = useAuth();
  const [selectedFile, setSelectedFile] = useState(null);
  const [validationError, setValidationError] = useState(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileChange = (file) => {
    if (!isAuthenticated) {
      openAuthModal();
      return;
    }
    if (!file) return;
    const validation = validatePcapFile(file);
    if (!validation.valid) {
      setValidationError(validation.error);
      setSelectedFile(null);
      return;
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (!isAuthenticated) {
      openAuthModal();
      return;
    }
    if (uploading) return;
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleFileChange(files[0]);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();

    if (!loading) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (event) => {
    if (!event.currentTarget.contains(event.relatedTarget)) {
      setIsDragging(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!isAuthenticated) {
      openAuthModal();
      return;
    }
    if (!selectedFile || uploading) return;
    onUpload(selectedFile);
  };

  const handleUpload = () => {
    if (file && onUpload) {
      onUpload(file);
    }
  };

  const handleZoneClick = () => {
    if (!isAuthenticated) {
      openAuthModal();
      return;
    }
    if (!uploading) {
      fileInputRef.current?.click();
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={handleZoneClick}
        className={`relative border-2 border-dashed rounded-2xl p-6 sm:p-8 text-center transition-all cursor-pointer ${
          !isAuthenticated
            ? 'border-slate-800 bg-slate-900/30 hover:border-brand-500/40 hover:bg-slate-900/50'
            : isDragOver
            ? 'border-brand-400 bg-brand-500/10'
            : selectedFile
            ? 'border-brand-500/40 bg-slate-900/80'
            : 'border-slate-800 hover:border-slate-700 bg-slate-900/40 hover:bg-slate-900/60'
        } ${uploading ? 'opacity-50 pointer-events-none' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          onChange={(e) => handleFileChange(e.target.files?.[0])}
          className="hidden"
          disabled={uploading}
        />

        {selectedFile ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-brand-500/20 text-brand-400 flex items-center justify-center border border-brand-500/30">
              <FileCode className="w-6 h-6" />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-100 flex items-center justify-center gap-2">
                <span>{selectedFile.name}</span>
                <button
                  type="button"
                  onClick={handleClear}
                  className="text-slate-400 hover:text-rose-400 p-0.5 rounded-full hover:bg-slate-800 transition-colors"
                  title="Remove file"
                  aria-label="Remove selected file"
                >
                  <X className="w-4 h-4" />
                </button>
              </p>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                {formatBytes(selectedFile.size)} • Valid PCAP ready for inspection
              </p>
            </div>

            {/* Actions */}
            <div className="flex w-full shrink-0 flex-col gap-2 sm:flex-row lg:w-auto">
              <button
                type="button"
                onClick={handleClear}
                disabled={loading}
                className="ui-button ui-button-secondary w-full sm:w-auto"
              >
                <X className="h-3.5 w-3.5" />
                Change file
              </button>

              <button
                type="button"
                onClick={handleUpload}
                disabled={loading}
                className="ui-button ui-button-primary w-full sm:w-auto"
              >
                {loading ? (
                  <>
                    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    Launch analysis
                    <ArrowRight className="h-3.5 w-3.5" />
                  </>
                )}
              </button>
            </div>
          </div>
        ) : !isAuthenticated ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <Lock className="w-6 h-6 text-amber-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-200">
                Sign in required to upload PCAP files
              </p>
              <p className="text-xs text-slate-400 mt-1 max-w-sm">
                Node.js API Gateway requires an authenticated analyst account with a valid JWT token.
              </p>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                openAuthModal();
              }}
              className="mt-1 inline-flex items-center gap-1.5 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-brand-600/20 transition-all"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In / Register to Upload</span>
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400 group-hover:text-brand-400">
              <UploadCloud className="w-6 h-6 text-brand-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-slate-200">
                <span className="text-brand-400 font-semibold">Click to upload</span> or drag and drop packet capture
              </p>
              <p className="text-xs text-slate-400 mt-1">
                Supported: <span className="font-mono text-slate-300">.pcap</span>, <span className="font-mono text-slate-300">.pcapng</span> (Max 100 MB)
              </p>
            </div>
          </div>

          <div className="min-w-0">
            <p className="text-xs font-semibold text-red-800">
              Upload validation failed
            </p>

            <p className="mt-0.5 text-xs leading-5 text-red-700">
              {error}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

/* ===============================================================
   FORMAT BADGE
=============================================================== */

function FormatBadge({ label }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[10px] font-semibold text-slate-600 shadow-sm">
      <FileCode2 className="h-3 w-3 text-brand-500" />
      {label}
    </span>
  );
}