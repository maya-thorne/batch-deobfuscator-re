import React from 'react';

const Sidebar = ({ activeTab, setActiveTab }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '⚡' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
    { id: 'about', label: 'Documentation', icon: '📖' }
  ];

  return (
    <div className="sidebar" style={{
      width: '260px',
      height: '100%',
      backgroundColor: 'var(--surface-color)',
      borderRight: '1px solid var(--border-color)',
      padding: '24px 16px',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 10
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '32px', padding: '0 8px' }}>
        <div style={{ 
          width: '32px', 
          height: '32px', 
          borderRadius: '4px',
          overflow: 'hidden',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          border: '1px solid var(--border-color)',
          backgroundColor: '#000'
        }}>
          <img 
            src="/logo.jpg" 
            style={{ 
              width: '100%',
              height: '100%',
              objectFit: 'cover',
              transform: 'scale(4.2) translateY(5%)', // Targeted zoom and slight nudge down
              filter: 'brightness(1.1)' // Make it pop
            }} 
          />
        </div>
        <h1 style={{ fontSize: '18px', fontWeight: '600', letterSpacing: '-0.5px' }}>BatchGuard <span style={{ color: 'var(--text-secondary)', fontSize: '12px', fontWeight: '400' }}>PRO</span></h1>
      </div>

      <nav style={{ flex: 1 }}>
        {menuItems.map(item => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '10px 12px',
              border: 'none',
              background: activeTab === item.id ? 'rgba(255, 255, 255, 0.05)' : 'transparent',
              borderRadius: '6px',
              color: activeTab === item.id ? 'var(--text-primary)' : 'var(--text-secondary)',
              fontSize: '14px',
              fontWeight: activeTab === item.id ? '500' : '400',
              marginBottom: '4px',
              textAlign: 'left'
            }}
          >
            <span style={{ fontSize: '16px' }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div style={{ padding: '8px', borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
        <div style={{ fontSize: '11px', color: 'var(--text-secondary)', opacity: 0.6 }}>
          Version 1.0.4 (Stable)
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
