import React, { useState, useCallback } from 'react';
import { obfuscateBatchFile } from '../logic/obfuscator';

const DropZone = ({ settings }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [processedFile, setProcessedFile] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleFile = async (file) => {
    if (!file.name.endsWith('.bat') && !file.name.endsWith('.cmd')) {
      alert("Please select a .bat or .cmd file");
      return;
    }

    setIsProcessing(true);
    try {
      const result = await obfuscateBatchFile(file, { scramble: settings?.scrambleEnabled });
      // Simulate professional processing delay for better UX
      setTimeout(() => {
        setProcessedFile(result);
        setIsProcessing(false);
      }, 1200);
    } catch (err) {
      console.error(err);
      setIsProcessing(false);
    }
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, []);

  const downloadFile = () => {
    if (!processedFile) return;
    const url = URL.createObjectURL(processedFile.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = processedFile.fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ padding: '40px', maxWidth: '800px', margin: '0 auto', width: '100%' }}>
      <header style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '8px' }}>Security Dashboard</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>Protect your scripts from unauthorized viewing and inspection.</p>
      </header>

      {!processedFile ? (
        <div
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={onDrop}
          className="pro-card animate-fade-in"
          style={{
            height: '320px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            border: `2px dashed ${isDragging ? 'var(--primary-color)' : 'var(--border-color)'}`,
            backgroundColor: isDragging ? 'rgba(0, 120, 212, 0.05)' : 'var(--surface-color)',
            transition: 'all 0.3s ease',
            position: 'relative',
            cursor: 'pointer'
          }}
          onClick={() => document.getElementById('file-input').click()}
        >
          <input 
            id="file-input"
            type="file" 
            accept=".bat,.cmd" 
            style={{ display: 'none' }} 
            onChange={(e) => e.target.files[0] && handleFile(e.target.files[0])}
          />
          
          {isProcessing ? (
            <div style={{ textAlign: 'center' }}>
              <div className="spinner" style={{ 
                width: '40px', 
                height: '40px', 
                border: '3px solid rgba(255,255,255,0.1)', 
                borderTop: '3px solid var(--primary-color)',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                margin: '0 auto 16px'
              }}></div>
              <p style={{ fontWeight: '500' }}>Applying Header Injection...</p>
            </div>
          ) : (
            <>
              <div style={{ fontSize: '48px', marginBottom: '16px', opacity: 0.8 }}>📄</div>
              <p style={{ fontSize: '16px', fontWeight: '500', marginBottom: '8px' }}>
                Drag and drop your Batch file here
              </p>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                or click to browse from your computer
              </p>
            </>
          )}
        </div>
      ) : (
        <div className="pro-card animate-fade-in" style={{ padding: '32px', textAlign: 'center' }}>
          <div style={{ 
            width: '64px', 
            height: '64px', 
            background: 'rgba(16, 185, 129, 0.1)', 
            borderRadius: '50%',
            color: 'var(--success-color)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '32px',
            margin: '0 auto 20px'
          }}>✓</div>
          <h3 style={{ fontSize: '20px', fontWeight: '600', marginBottom: '8px' }}>Obfuscation Complete</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px' }}>
            Result: {processedFile.fileName} ({Math.round(processedFile.newSize / 1024 * 10) / 10} KB)
          </p>
          
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button 
              onClick={downloadFile}
              style={{
                background: 'var(--primary-color)',
                color: 'white',
                border: 'none',
                padding: '10px 24px',
                borderRadius: '6px',
                fontWeight: '500',
                fontSize: '14px'
              }}
            >
              Download Export
            </button>
            <button 
              onClick={() => setProcessedFile(null)}
              style={{
                background: 'transparent',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                padding: '10px 24px',
                borderRadius: '6px',
                fontWeight: '500',
                fontSize: '14px'
              }}
            >
              Process Another
            </button>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default DropZone;
