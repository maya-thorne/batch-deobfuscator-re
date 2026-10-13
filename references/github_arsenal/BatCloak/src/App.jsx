import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import DropZone from './components/DropZone';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [settings, setSettings] = useState({
    scrambleEnabled: false
  });

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', background: 'var(--bg-color)' }}>
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <main style={{ 
        flex: 1, 
        overflowY: 'auto', 
        padding: '32px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center'
      }}>
        {activeTab === 'dashboard' && <DropZone settings={settings} />}
        
        {activeTab === 'settings' && (
          <div className="animate-fade-in" style={{ maxWidth: '600px', width: '100%', padding: '40px' }}>
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '24px' }}>System Settings</h2>
            <div className="pro-card" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <div>
                  <h4 style={{ fontSize: '14px', fontWeight: '500' }}>Header Injection (Stealth Mode)</h4>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Trick text editors into failing to read script content.</p>
                </div>
                <div style={{ color: 'var(--success-color)', fontSize: '12px', fontWeight: 'bold' }}>ALWAYS ON</div>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h4 style={{ fontSize: '14px', fontWeight: '500' }}>Variable Scrambling</h4>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Randomize SET variable names for deeper protection.</p>
                </div>
                <button 
                  onClick={() => setSettings(s => ({ ...s, scrambleEnabled: !s.scrambleEnabled }))}
                  style={{ 
                    padding: '6px 12px', 
                    borderRadius: '4px', 
                    border: '1px solid var(--border-color)',
                    background: settings.scrambleEnabled ? 'var(--primary-color)' : 'transparent',
                    color: '#fff',
                    fontSize: '11px',
                    fontWeight: 'bold'
                  }}
                >
                  {settings.scrambleEnabled ? 'ENABLED' : 'DISABLED'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'about' && (
          <div className="animate-fade-in" style={{ maxWidth: '600px', width: '100%', padding: '40px' }}>
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '24px' }}>Documentation</h2>
            <div className="pro-card" style={{ padding: '24px' }}>
              <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: '1.6' }}>
                BatchGuard Pro uses a specialized UTF-16 Byte Order Mark (BOM) injection technique. 
                By prepending the sequence <code>FF FE 26 63 6C 73 0D 0A</code> to your script, 
                we create an encoding mismatch that makes the file unreadable in standard text editors like Notepad, 
                while remaining fully executable by the Windows Command Processor.
              </p>
              <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                Developed by Sunil to provide high-fidelity security tools for batch automation.
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
