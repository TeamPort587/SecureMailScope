import React, { useRef, useState } from 'react';
import {
  UploadCloud,
  FileCode2,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  X,
  FileCheck2,
  ShieldCheck,
} from 'lucide-react';

export default function UploadForm({ onUpload, loading = false }) {
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);

  const inputRef = useRef(null);

  const MAX_SIZE = 100 * 1024 * 1024;

  const validateFile = (selectedFile) => {
    if (!selectedFile) return false;

    const validExtensions = ['.pcap', '.pcapng'];
    const fileName = selectedFile.name.toLowerCase();

    if (
      !validExtensions.some((ext) =>
        fileName.endsWith(ext)
      )
    ) {
      setError(
        'Please select a valid .pcap or .pcapng capture file.'
      );
      return false;
    }

    if (selectedFile.size > MAX_SIZE) {
      setError('File size must be smaller than 100 MB.');
      return false;
    }

    setError('');
    return true;
  };

  const handleFile = (selectedFile) => {
    if (validateFile(selectedFile)) {
      setFile(selectedFile);
    }
  };

  const handleInputChange = (event) => {
    const selectedFile = event.target.files?.[0];

    if (selectedFile) {
      handleFile(selectedFile);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);

    const droppedFile = event.dataTransfer.files?.[0];

    if (droppedFile) {
      handleFile(droppedFile);
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

  const handleClear = () => {
    setFile(null);
    setError('');

    if (inputRef.current) {
      inputRef.current.value = '';
    }
  };

  const handleUpload = () => {
    if (file && onUpload) {
      onUpload(file);
    }
  };

  return (
    <div className="w-full">
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={handleInputChange}
        disabled={loading}
      />

      {!file ? (
        <div
          role="button"
          tabIndex={loading ? -1 : 0}
          onClick={() => {
            if (!loading) {
              inputRef.current?.click();
            }
          }}
          onKeyDown={(event) => {
            if (
              !loading &&
              (event.key === 'Enter' ||
                event.key === ' ')
            ) {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          aria-disabled={loading}
          className={`upload-dropzone group relative flex min-h-[250px] cursor-pointer flex-col items-center justify-center rounded-2xl px-5 py-8 text-center outline-none sm:min-h-[270px] sm:px-8 ${
            isDragging
              ? 'border-brand-500 bg-brand-50 shadow-[0_8px_30px_rgba(14,165,233,0.12)]'
              : ''
          } ${loading ? 'cursor-not-allowed opacity-60' : ''}`}
        >
          {/* Decorative background */}
          <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-2xl">
            <div
              className={`absolute -right-16 -top-16 h-40 w-40 rounded-full bg-brand-400/5 blur-3xl transition-opacity ${
                isDragging ? 'opacity-100' : 'opacity-60'
              }`}
            />

            <div className="absolute -bottom-20 -left-16 h-40 w-40 rounded-full bg-brand-400/5 blur-3xl" />
          </div>

          {/* Upload icon */}
          <div
            className={`upload-icon relative mb-5 flex h-14 w-14 items-center justify-center rounded-2xl transition-all duration-200 ${
              isDragging
                ? 'scale-105 border-brand-300 bg-brand-50'
                : 'group-hover:-translate-y-0.5'
            }`}
          >
            <UploadCloud
              className={`h-7 w-7 transition-colors ${
                isDragging
                  ? 'text-brand-600'
                  : 'text-brand-500'
              }`}
            />
          </div>

          {/* Main copy */}
          <div className="relative">
            <p className="text-sm font-semibold text-slate-900 sm:text-[15px]">
              {isDragging ? (
                'Drop your capture here'
              ) : (
                <>
                  <span className="text-brand-600">
                    Choose a PCAP file
                  </span>{' '}
                  or drag and drop
                </>
              )}
            </p>

            <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-500">
              Upload a network capture to reconstruct email
              sessions and evaluate protocol security.
            </p>
          </div>

          {/* Supported formats */}
          <div className="relative mt-5 flex flex-wrap items-center justify-center gap-2">
            <FormatBadge label="PCAP" />
            <FormatBadge label="PCAPNG" />

            <span className="px-1 text-[10px] text-slate-400">
              •
            </span>

            <span className="text-[10px] font-medium text-slate-500">
              Maximum 100 MB
            </span>
          </div>

          {/* Security hint */}
          <div className="relative mt-5 flex items-center gap-1.5 text-[10px] font-medium text-slate-400">
            <ShieldCheck className="h-3 w-3 text-emerald-600" />
            Capture is processed by the analysis engine
          </div>
        </div>
      ) : (
        /* =====================================================
           SELECTED FILE
        ====================================================== */

        <div className="rounded-2xl border border-brand-200 bg-brand-50/40 p-4 sm:p-5">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            {/* File information */}
            <div className="flex min-w-0 items-center gap-4">
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-brand-200 bg-white shadow-sm">
                <FileCheck2 className="h-5 w-5 text-brand-600" />
              </div>

              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <p
                    className="max-w-[420px] truncate text-sm font-semibold text-slate-900"
                    title={file.name}
                  >
                    {file.name}
                  </p>

                  <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[10px] font-semibold text-emerald-700">
                    VALID
                  </span>
                </div>

                <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
                  <span>
                    {(
                      file.size /
                      (1024 * 1024)
                    ).toFixed(2)}{' '}
                    MB
                  </span>

                  <span className="text-slate-300">
                    •
                  </span>

                  <span className="font-medium uppercase">
                    {file.name.split('.').pop()}
                  </span>

                  <span className="text-slate-300">
                    •
                  </span>

                  <span className="inline-flex items-center gap-1 text-emerald-700">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Ready for analysis
                  </span>
                </div>
              </div>
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
        </div>
      )}

      {/* =====================================================
          VALIDATION ERROR
      ====================================================== */}

      {error && (
        <div className="mt-3 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white">
            <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
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