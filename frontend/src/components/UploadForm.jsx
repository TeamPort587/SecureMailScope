import React, { useState, useRef } from 'react';
import { UploadCloud, FileCode, CheckCircle, AlertTriangle, ArrowRight, X } from 'lucide-react';
import { validatePcapFile } from '../utils/validation';
import { formatBytes } from '../utils/formatters';

export default function UploadForm({ onUpload, uploading = false }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [validationError, setValidationError] = useState(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileChange = (file) => {
    if (!file) return;
    const validation = validatePcapFile(file);
    if (!validation.valid) {
      setValidationError(validation.error);
      setSelectedFile(null);
      return;
    }
    setValidationError(null);
    setSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (uploading) return;
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleFileChange(files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    if (!uploading) setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!selectedFile || uploading) return;
    onUpload(selectedFile);
  };

  const handleClear = (e) => {
    e.stopPropagation();
    setSelectedFile(null);
    setValidationError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !uploading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-6 sm:p-8 text-center transition-all cursor-pointer ${
          isDragOver
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
            <div className="flex items-center gap-2 mt-2">
              <button
                type="submit"
                disabled={uploading}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white text-xs font-semibold shadow-lg shadow-brand-500/25 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"
              >
                <span>Launch Analysis</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Change File
              </button>
            </div>
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
        )}
      </div>

      {validationError && (
        <div className="mt-3 p-3 rounded-xl bg-red-950/40 border border-red-500/30 flex items-center gap-2.5 text-xs text-red-300">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{validationError}</span>
        </div>
      )}
    </form>
  );
}
